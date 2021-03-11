require 'json'
require 'csv'
require 'heimdall_tools/hdf'
require 'utilities/xml_to_hash'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

CWE_NIST_MAPPING_FILE = File.join(RESOURCE_DIR, 'cwe-nist-mapping.csv')

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
  class JfrogXrayMapper
    def initialize(xray_json, name=nil, verbose = false)
      @xray_json = xray_json
      @verbose = verbose

      begin
        @cwe_nist_mapping = parse_mapper
        @project = JSON.parse(xray_json)

      rescue StandardError => e
        raise "Invalid JFrog Xray JSON file provided Exception: #{e}"
      end
    end

    def finding(vulnerability)
      finding = {}
      finding['status'] = 'failed'
      finding['code_desc'] = []
      finding['code_desc'] << "source_comp_id : #{vulnerability['source_comp_id'].to_s }"
      finding['code_desc'] << "vulnerable_versions : #{vulnerability['component_versions']['vulnerable_versions'].to_s }"
      finding['code_desc'] << "fixed_versions : #{vulnerability['component_versions']['fixed_versions'].to_s }"
      finding['code_desc'] << "issue_type : #{vulnerability['issue_type'].to_s }"
      finding['code_desc'] << "provider : #{vulnerability['provider'].to_s }"
      finding['code_desc'] = finding['code_desc'].join("\n")
      finding['run_time'] = NA_FLOAT

      # Xray results does not profile scan timestamp; using current time to satisfy HDF format
      finding['start_time'] = NA_STRING
      [finding]
    end

    def nist_tag(cweid)
      entries = @cwe_nist_mapping.select { |x| cweid.include?(x[:cweid].to_s) && !x[:nistid].nil? }
      tags = entries.map { |x| x[:nistid] }
      tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def parse_identifiers(vulnerability, ref)
      # Extracting id number from reference style CWE-297
      vulnerability['component_versions']['more_details']['cves'][0][ref.downcase].map { |e| e.split("#{ref}-")[1]  }
      rescue
        return []
    end

    def impact(severity)
      IMPACT_MAPPING[severity.downcase.to_sym]
    end

    def parse_mapper
      csv_data = CSV.read(CWE_NIST_MAPPING_FILE, **{ encoding: 'UTF-8',
                                                   headers: true,
                                                   header_converters: :symbol,
                                                   converters: :all })
      csv_data.map(&:to_hash)
    end

    def desc_tags(data, label)
      { "data": data || NA_STRING, "label": label || NA_STRING }
    end

    # Xray report could have multiple vulnerability entries for multiple findings of same issue type.
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
      vulnerability_count = 0
      @project['data'].uniq.each do | vulnerability |
        printf("\rProcessing: %s", $spinner.next)
        
        vulnerability_count +=1
        item = {}
        item['tags']               = {}
        item['descriptions']       = []
        item['refs']               = NA_ARRAY
        item['source_location']    = NA_HASH
        item['descriptions']       = NA_ARRAY

        # Xray JSONs might note have `id` fields populated. 
        # If thats a case MD5 hash is used to collapse vulnerability findings of the same type.
        item['id']                 = vulnerability['id'].empty? ? OpenSSL::Digest::MD5.digest(vulnerability['summary'].to_s).unpack("H*")[0].to_s : vulnerability['id']
        item['title']              = vulnerability['summary'].to_s
        item['desc']               = vulnerability['component_versions']['more_details']['description'].to_s
        item['impact']             = impact(vulnerability['severity'].to_s) 
        item['code']               = NA_STRING
        item['results']            = finding(vulnerability)

        item['tags']['nist']       = nist_tag( parse_identifiers( vulnerability, 'CWE') )
        item['tags']['cweid']      = parse_identifiers( vulnerability, 'CWE')

        controls << item
      end

      controls = collapse_duplicates(controls)
      results = HeimdallDataFormat.new(profile_name: "JFrog Xray Scan",
                                       version: NA_STRING,
                                       title: "JFrog Xray Scan", 
                                       summary: "Continuous Security and Universal Artifact Analysis",
                                       controls: controls)
      results.to_hdf
    end
  end
end
