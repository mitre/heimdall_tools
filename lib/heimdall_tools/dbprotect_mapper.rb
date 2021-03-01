require 'json'
require 'csv'
require 'heimdall_tools/hdf'
require 'utilities/xml_to_hash'

IMPACT_MAPPING = {
  High: 0.7,
  Medium: 0.5,
  Low: 0.3,
  Informational: 0.0
}.freeze

# rubocop:disable Metrics/AbcSize

module HeimdallTools
  class DBProtectMapper
    def initialize(xml, name=nil, verbose = false)
      @verbose = verbose

      begin
        dataset = xml_to_hash(xml)
        @entries = compile_findings(dataset['dataset'])

      rescue StandardError => e
        raise "Invalid DBProtect XML file provided Exception: #{e};\nNote that XML must be of kind `Check Results Details`."
      end

    end

    def to_hdf
      controls = []
      @entries.each do |entry|
        @item = {}
        @item['id']                 = entry['Check ID']
        @item['title']              = entry['Check']
        @item['desc']               = format_desc(entry)
        @item['impact']             = impact(entry['Risk DV'])
        @item['tags']               = {}
        @item['descriptions']       = []
        @item['refs']               = NA_ARRAY
        @item['source_location']    = NA_HASH
        @item['code']               = ''
        @item['results']            = finding(entry)

        controls << @item
      end
      controls = collapse_duplicates(controls)
      results = HeimdallDataFormat.new(profile_name: @entries.first['Policy'],
                                       version: "",
                                       title: @entries.first['Job Name'],
                                       summary: format_summary(@entries.first),
                                       controls: controls)
      results.to_hdf
    end

    private

    def compile_findings(dataset)
      keys = dataset['metadata']['item'].map{ |e| e['name']}
      findings = dataset['data']['row'].map { |e| Hash[keys.zip(e['value'])] }
      findings
    end

    def format_desc(entry)
      text = []
      text << "Task : #{entry['Task']}"
      text << "Check Category : #{entry['Check Category']}"
      text.join("; ")
    end

    def format_summary(entry)
      text = []
      text << "Organization : #{entry['Organization']}"
      text << "Asset : #{entry['Check Asset']}"
      text << "Asset Type : #{entry['Asset Type']}"
      text << "IP Address, Port, Instance : #{entry['Asset Type']}"
      text << "IP Address, Port, Instance : #{entry['IP Address, Port, Instance']}"
      text.join("\n")
    end

    def finding(entry)
      finding = {}

      finding['code_desc'] = entry['Details']
      finding['run_time'] = 0.0
      finding['start_time'] = entry['Date']

      case entry['Result Status']
      when 'Fact'
        finding['status'] = 'skipped'
      when 'Failed'
        finding['status'] = 'failed'
        finding['backtrace'] = ["DB Protect Failed Check"]
      when 'Finding'
        finding['status'] = 'failed'
      when 'Not A Finding'
        finding['status'] = 'passed'
      when 'Skipped'
        finding['status'] = 'skipped'
      else 
        finding['status'] = 'skipped'
      end
      [finding]
    end

    def impact(severity)
      IMPACT_MAPPING[severity.to_sym]
    end

    # DBProtect report could have multiple issue entries for multiple findings of same issue type.
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


  end
end
