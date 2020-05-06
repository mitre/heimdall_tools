require 'json'
require 'csv'
require 'heimdall_tools/hdf'
require 'utilities/xml_to_hash'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

NESSUS_PLUGINS_NIST_MAPPING_FILE =   File.join(RESOURCE_DIR, 'nessus-plugins-nist-mapping.csv')

IMPACT_MAPPING = {
  Info: 0.0,
  Low: 0.3,
  Medium: 0.5,
  High: 0.7,
  Critical: 0.9,
}.freeze

DEFAULT_NIST_TAG = ["unmapped"].freeze

NA_PLUGIN_OUTPUT = "This Nessus Plugin does not provide output message.".freeze

# rubocop:disable Metrics/AbcSize

module HeimdallTools
  class NessusMapper
    def initialize(nessus_xml, verbose = false)
      @nessus_xml = nessus_xml
      @verbose = verbose

      begin
        @cwe_nist_mapping = parse_mapper
        @data = xml_to_hash(nessus_xml)

        @reports = extract_report
        @scaninfo = extract_scaninfo
      rescue StandardError => e
        raise "Invalid Nessus XML file provided Exception: #{e}"
      end

    end

    def extract_report
      begin
        # When there are multiple hosts in the nessus report ReportHost field is an array
        # When there is only one host in the nessus report ReportHost field is a hash
        # Array() converts ReportHost to array in case there is only one host
        reports = @data['NessusClientData_v2']['Report']['ReportHost']
        reports.kind_of?(Array) ? reports : [reports]
      rescue StandardError => e
        raise "Invalid Nessus XML file provided Exception: #{e}"
      end
    end

    def extract_scaninfo
      begin
        policy = @data['NessusClientData_v2']['Policy']
        info = {}

        info['policyName'] = policy['policyName']
        info['version'] = policy['Preferences']['ServerPreferences']['preference'].select {|x| x['name'].eql? 'sc_version'}.first['value']
        info
      rescue StandardError => e
        raise "Invalid Nessus XML file provided Exception: #{e}"
      end
    end

    def extract_timestamp(report)
      begin
        timestamp = report['HostProperties']['tag'].select {|x| x['name'].eql? 'HOST_START'}.first['text']
      rescue StandardError => e
        raise "Invalid Nessus XML file provided Exception: #{e}"
      end
    end

    def format_desc(issue)
      desc = ''
      desc += "Plugin Family: #{issue['pluginFamily']}; "
      desc += "Port: #{issue['port']}; "
      desc += "Protocol: #{issue['protocol']};"
      desc
    end

    def finding(issue, timestamp)
      finding = {}
      finding['status'] = 'failed'
      finding['code_desc'] = issue['plugin_output'] || NA_PLUGIN_OUTPUT
      finding['run_time'] = NA_FLOAT
      finding['start_time'] = timestamp
      [finding]
    end

    def nist_tag(pluginfamily, pluginid)
      entries = @cwe_nist_mapping.select { |x| (x[:pluginfamily].eql?(pluginfamily) && (x[:pluginid].eql?('*') || x[:pluginid].eql?(pluginid.to_i)) ) }
      tags = entries.map { |x| [x[:nistid].split('|'), "Rev_#{x[:rev]}"] }
      tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def impact(severity)
      case severity
      when "0"
        IMPACT_MAPPING[:Info]
      when "1"
        IMPACT_MAPPING[:Low]
      when "2"
        IMPACT_MAPPING[:Medium]
      when "3"
        IMPACT_MAPPING[:High]
      when "4"
        IMPACT_MAPPING[:Critical]
      else
        -1
      end
    end

    def parse_mapper
      csv_data = CSV.read(NESSUS_PLUGINS_NIST_MAPPING_FILE, { encoding: 'UTF-8',
                                                   headers: true,
                                                   header_converters: :symbol,
                                                   converters: :all })
      csv_data.map(&:to_hash)
    end

    def desc_tags(data, label)
      { "data": data || NA_STRING, "label": label || NA_STRING }
    end

    # Nessus report could have multiple issue entries for multiple findings of same issue type.
    # The meta data is identical across entries 
    # method collapse_duplicates return unique controls with applicable findings collapsed into it.
    def collapse_duplicates(controls)
      unique_controls = []

      controls.map { |x| x['id'] }.uniq.each do |id|
        collapsed_results = controls.select { |x| x['id'].eql?(id) }.map {|x| x['results']}
        unique_control = controls.find { |x| x['id'].eql?(id) }
        unique_control['results'] = collapsed_results.flatten
        unique_controls << unique_control
      end
      unique_controls
    end

    def to_hdf
      host_results = {}
      @reports.each do | report|
        # Under current version of the converter `Policy Compliance` items are ignored
        report_items = report['ReportItem'].select {|x| !x['pluginFamily'].eql? 'Policy Compliance'}

        controls = []
        report_items.each do | item |
          @item = {}
          @item['id']                 = item['pluginID'].to_s
          @item['title']              = item['pluginName'].to_s
          @item['desc']               = format_desc(item).to_s
          @item['impact']             = impact(item['severity'])
          @item['tags']               = {}
          @item['descriptions']       = []
          @item['refs']               = NA_ARRAY
          @item['source_location']    = NA_HASH
          @item['tags']['nist']       = nist_tag(item['pluginFamily'],item['pluginID'])
          @item['code']               = ''
          @item['results']            = finding(item, extract_timestamp(report))
          controls << @item
        end
        controls = collapse_duplicates(controls)
        results = HeimdallDataFormat.new(profile_name: "Nessus #{@scaninfo['policyName']}",
                                         version: @scaninfo['version'],
                                         title: "Nessus #{@scaninfo['policyName']}",
                                         summary: "Nessus #{@scaninfo['policyName']}",
                                         controls: controls,
                                         target_id: report['name'])
        host_results[report['name']] = results.to_hdf
      end
      host_results
    end
  end
end
