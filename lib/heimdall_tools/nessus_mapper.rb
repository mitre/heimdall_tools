require 'json'
require 'csv'
require 'heimdall_tools/hdf'
require 'utilities/xml_to_hash'
require 'nokogiri'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

NESSUS_PLUGINS_NIST_MAPPING_FILE =   File.join(RESOURCE_DIR, 'nessus-plugins-nist-mapping.csv')
U_CCI_LIST =   File.join(RESOURCE_DIR, 'U_CCI_List.xml')

IMPACT_MAPPING = {
  Info: 0.0,
  Low: 0.3,
  Medium: 0.5,
  High: 0.7,
  Critical: 0.9,
}.freeze

DEFAULT_NIST_TAG = ["unmapped"].freeze

# Nessus results file 800-53 refs does not contain Nist rev version. Using this default
# version in that case
DEFAULT_NIST_REV = 'Rev_4'.freeze

NA_PLUGIN_OUTPUT = "This Nessus Plugin does not provide output message.".freeze

# rubocop:disable Metrics/AbcSize

# Loading spinner sign
$spinner = Enumerator.new do |e|
  loop do
    e.yield '|'
    e.yield '/'
    e.yield '-'
    e.yield '\\'
  end
end

module HeimdallTools
  class NessusMapper
    def initialize(nessus_xml, verbose = false)
      @nessus_xml = nessus_xml
      @verbose = verbose
      read_cci_xml
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

    def parse_refs(refs, key)
      refs.split(',').map { |x| x.split('|')[1] if x.include?(key) }.compact
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
      # if compliance-result field, this is a policy compliance result entry
      # nessus policy compliance result provides a pass/fail data
      # For non policy compliance  results are defaulted to failed
      if issue['compliance-result']
        finding['status'] = issue['compliance-result'].eql?('PASSED') ? 'passed' : 'failed'
      else
        finding['status'] = 'failed'
      end

      if issue['description']
        finding['code_desc'] = issue['description'].to_s || NA_PLUGIN_OUTPUT
      else
        finding['code_desc'] = issue['plugin_output'] || NA_PLUGIN_OUTPUT
      end
      finding['run_time'] = NA_FLOAT
      finding['start_time'] = timestamp
      [finding]
    end

    def read_cci_xml
      cci_list_path = File.join(File.dirname(__FILE__), '../data/U_CCI_List.xml')
      @cci_xml = Nokogiri::XML(File.open(cci_list_path))
      @cci_xml.remove_namespaces!
    rescue StandardError => e
      puts "Exception: #{e.message}"
    end

    def cci_nist_tag(cci_refs)
      nist_tags = []
      cci_refs.each do | cci_ref |
        item_node = @cci_xml.xpath("//cci_list/cci_items/cci_item[@id='#{cci_ref}']")[0] unless @cci_xml.nil?
        unless item_node.nil?
          nist_ref = item_node.xpath('./references/reference[not(@version <= preceding-sibling::reference/@version) and not(@version <=following-sibling::reference/@version)]/@index').text
          nist_ver = item_node.xpath('./references/reference[not(@version <= preceding-sibling::reference/@version) and not(@version <=following-sibling::reference/@version)]/@version').text
        end
        nist_tags << nist_ref
        nist_tags << "Rev_#{nist_ver}"
      end
      nist_tags
    end

    def plugin_nist_tag(pluginfamily, pluginid)
      entries = @cwe_nist_mapping.select { |x| (x[:pluginfamily].eql?(pluginfamily) && (x[:pluginid].eql?('*') || x[:pluginid].eql?(pluginid.to_i)) ) }
      tags = entries.map { |x| [x[:nistid].split('|'), "Rev_#{x[:rev]}"] }
      tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def impact(severity)
      # Map CAT levels and Plugin severity to HDF impact levels
      case severity
      when "0"
        IMPACT_MAPPING[:Info]
      when "1","III"
        IMPACT_MAPPING[:Low]
      when "2","II"
        IMPACT_MAPPING[:Medium]
      when "3","I"
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
        controls = []
        report['ReportItem'].each do | item |
          printf("\rProcessing: %s", $spinner.next)
          @item = {}
          @item['tags']               = {}
          @item['descriptions']       = []
          @item['refs']               = NA_ARRAY
          @item['source_location']    = NA_HASH

          # Nessus results field set are different for 'Policy Compliance' plug-in family vs other plug-in families
          # Following if conditions capture compliance* if it exists else it will default to plugin* fields
          # Current version covers STIG based 'Policy Compliance' results
          # TODO Cover cases for 'Policy Compliance' results based on CIS
          if item['compliance-reference']
            @item['id']                 = parse_refs(item['compliance-reference'],'Vuln-ID').join.to_s
          else
            @item['id']                 = item['pluginID'].to_s
          end
          if item['compliance-check-name']
            @item['title']              = item['compliance-check-name'].to_s
          else
            @item['title']              = item['pluginName'].to_s
          end
          if item['compliance-info']
            @item['desc']              = item['compliance-info'].to_s
          else
            @item['desc']              = format_desc(item).to_s
          end
          if item['compliance-reference']
            @item['impact']            = impact(parse_refs(item['compliance-reference'],'CAT').join.to_s)
          else
            @item['impact']            = impact(item['severity']) 
          end
          if item['compliance-reference']
            @item['tags']['nist']     = cci_nist_tag(parse_refs(item['compliance-reference'],'CCI'))
          else
            @item['tags']['nist']     = plugin_nist_tag(item['pluginFamily'],item['pluginID'])
          end
          if item['compliance-solution']
            @item['descriptions']       <<  desc_tags(item['compliance-solution'], 'check')
          end

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
