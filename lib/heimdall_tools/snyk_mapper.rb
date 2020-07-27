require 'json'
require 'csv'
require 'heimdall_tools/hdf'
require 'utilities/xml_to_hash'
require 'pp'


RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

CWE_NIST_MAPPING_FILE = File.join(RESOURCE_DIR, 'cwe-nist-mapping.csv')

IMPACT_MAPPING = {
  high: 0.7,
  medium: 0.5,
  low: 0.3,
}.freeze

CWE_REGEX = 'CWE-(\d*):'.freeze

DEFAULT_NIST_TAG = ["blah"].freeze

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
  class SnykMapper
    def initialize(synk_json, name=nil, verbose = false)
      @synk_json = synk_json
      @verbose = verbose

      begin
        @cwe_nist_mapping = parse_mapper
        @projects = JSON.parse(synk_json)

        # Cover single and multi-project scan use cases.
        unless @projects.kind_of?(Array)
          @projects = [ @projects ]
        end

      rescue StandardError => e
        raise "Invalid Snyk JSON file provided Exception: #{e}"
      end
    end

    def extract_scaninfo(project)
      info = {}
      begin
        info['policy'] = project['policy']
        info['version'] = '1.16.0'
        info['projectName'] = project['projectName']
        info['summary'] = project['summary']

        info
      rescue StandardError => e
        raise "Error extracting project info from Synk JSON file provided Exception: #{e}"
      end
    end

    def finding(vulnerability)
      finding = {}
      finding['status'] = 'failed'
      finding['code_desc'] = "From : [ #{vulnerability['from'].join(" , ").to_s } ]"
      finding['run_time'] = NA_FLOAT
      finding['start_time'] = Time.now.strftime("%a,%d %b %Y %X")
      [finding]
    end

    def nist_tag(cweid)
      entries = @cwe_nist_mapping.select { |x| cweid.include? x[:cweid].to_s }
      tags = entries.map { |x| x[:nistid] }
      tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def parse_identifiers(vulnerability, ref)
      # Extracting id number from reference style CWE-297
      vulnerability['identifiers'][ref].map { |e| e.split("#{ref}-")[1]  }
      rescue
        return []
    end

    def impact(severity)
      IMPACT_MAPPING[severity.to_sym]
    end

    def parse_mapper
      csv_data = CSV.read(CWE_NIST_MAPPING_FILE, { encoding: 'UTF-8',
                                                   headers: true,
                                                   header_converters: :symbol,
                                                   converters: :all })
      csv_data.map(&:to_hash)
    end

    def desc_tags(data, label)
      { "data": data || NA_STRING, "label": label || NA_STRING }
    end

    # Snyk report could have multiple vulnerability entries for multiple findings of same issue type.
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
      project_results = {}
      @projects.each do | project |
        controls = []
        project['vulnerabilities'].each do | vulnerability |
          printf("\rProcessing: %s", $spinner.next)

          @item = {}
          @item['tags']               = {}
          @item['descriptions']       = []
          @item['refs']               = NA_ARRAY
          @item['source_location']    = NA_HASH


          @item['title']              = vulnerability['title'].to_s
          @item['id']                 = vulnerability['id'].to_s
          @item['desc']               = vulnerability['description'].to_s
          @item['impact']            = impact(vulnerability['severity']) 
          @item['code']               = ''
          @item['results']            = finding(vulnerability)
          @item['tags']['nist']       = nist_tag( parse_identifiers( vulnerability, 'CWE') )
          @item['tags']['cweid']       = parse_identifiers( vulnerability, 'CWE')
          @item['tags']['cveid']       = parse_identifiers( vulnerability, 'CVE')
          @item['tags']['ghsaid']       = parse_identifiers( vulnerability, 'GHSA')

          controls << @item
        end
        controls = collapse_duplicates(controls)
        scaninfo = extract_scaninfo(project)
        results = HeimdallDataFormat.new(profile_name: "Snyk Policy: #{scaninfo['policy']}",
                                         version: scaninfo['version'],
                                         title: "Snyk Project: #{scaninfo['projectName']}",
                                         summary: "Snyk Summary: #{scaninfo['summary']}",
                                         controls: controls,
                                         target_id: scaninfo['projectName'])
        project_results[scaninfo['projectName']] = results.to_hdf
      end
      project_results
    end
  end
end
