require 'json'
require 'csv'
require 'heimdall_tools/hdf'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

NIKTO_NIST_MAPPING_FILE = File.join(RESOURCE_DIR, 'nikto-nist-mapping.csv')

IMPACT_MAPPING = {
  high: 0.7,
  medium: 0.5,
  low: 0.3,
}.freeze

DEFAULT_NIST_TAG = ["SA-11", "RA-5"].freeze

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
  class NiktoMapper
    def initialize(nikto_json, name=nil, verbose = false)
      @nikto_json = nikto_json
      @verbose = verbose

      begin
        @nikto_nist_mapping = parse_mapper
      rescue StandardError => e
        raise "Invalid Nikto to NIST mapping file: Exception: #{e}"
      end

        # TODO: Support Multi-target scan results
        # Nikto multi-target scans generate invalid format JSONs
        # Possible workaround to use https://stackoverflow.com/a/58209963/1670307

      begin
        @project = JSON.parse(nikto_json)
      rescue StandardError => e
        raise "Invalid Nikto JSON file provided\nNote: nikto_mapper does not support multi-target scan results\n\nException: #{e}"
      end
    end

    def extract_scaninfo(project)
      info = {}
      begin
        info['policy'] = 'Nikto Website Scanner'
        info['version'] = NA_STRING
        info['projectName'] = "Host: #{project['host']} Port: #{project['port']}"
        info['summary'] = "Banner: #{project['banner']}"

        info
      rescue StandardError => e
        raise "Error extracting project info from nikto JSON file provided Exception: #{e}"
      end
    end

    def finding(vulnerability)
      finding = {}
      finding['status'] = 'failed'
      finding['code_desc'] = "URL : #{vulnerability['url'].to_s } Method: #{vulnerability['method'].to_s}"
      finding['run_time'] = NA_FLOAT
      finding['start_time'] = NA_STRING
      [finding]
    end

    def nist_tag(niktoid)
      entries = @nikto_nist_mapping.select { |x| niktoid.eql?(x[:niktoid].to_s) }
      tags = entries.map { |x| x[:nistid] }
      tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def impact(severity)
      IMPACT_MAPPING[severity.to_sym]
    end

    def parse_mapper
      csv_data = CSV.read(NIKTO_NIST_MAPPING_FILE, **{ encoding: 'UTF-8',
                                                   headers: true,
                                                   header_converters: :symbol})
      csv_data.map(&:to_hash)
    end

    def desc_tags(data, label)
      { "data": data || NA_STRING, "label": label || NA_STRING }
    end

    # Nikto report could have multiple vulnerability entries for multiple findings of same issue type.  
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
      controls = []
      @project['vulnerabilities'].each do | vulnerability |
        printf("\rProcessing: %s", $spinner.next)

        item = {}
        item['tags']               = {}
        item['descriptions']       = []
        item['refs']               = NA_ARRAY
        item['source_location']    = NA_HASH
        item['descriptions']       = NA_ARRAY

        item['title']              = vulnerability['msg'].to_s
        item['id']                 = vulnerability['id'].to_s

        # Nikto results JSON does not description fields
        # Duplicating vulnerability msg field
        item['desc']               = vulnerability['msg'].to_s

        # Nitko does not provide finding severity; hard-coding severity to medium 
        item['impact']             = impact('medium') 
        item['code']               = NA_STRING
        item['results']            = finding(vulnerability)
        item['tags']['nist']       = nist_tag( vulnerability['id'].to_s )
        item['tags']['ösvdb']      = vulnerability['OSVDB']

        controls << item
      end

      controls = collapse_duplicates(controls)
      scaninfo = extract_scaninfo(@project)
      results = HeimdallDataFormat.new(profile_name: scaninfo['policy'],
                                       version: scaninfo['version'],
                                       title: "Nikto Target: #{scaninfo['projectName']}",
                                       summary: "Banner: #{scaninfo['summary']}",
                                       controls: controls,
                                       target_id: scaninfo['projectName'])
      results.to_hdf
    end
  end
end
