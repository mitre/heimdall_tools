require 'json'
require 'csv'
require 'heimdall_tools/hdf'
require 'utilities/xml_to_hash'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

CWE_NIST_MAPPING_FILE = File.join(RESOURCE_DIR, 'cwe-nist-mapping.csv')
OWASP_NIST_MAPPING_FILE = File.join(RESOURCE_DIR, 'owasp-nist-mapping.csv')

IMPACT_MAPPING = {
  Critical: 1.0,
  High: 0.7,
  Medium: 0.5,
  Low: 0.3,
  Best_Practice: 0.0,
  Information: 0.0
}.freeze

DEFAULT_NIST_TAG = ["SA-11", "RA-5", "Rev_4"].freeze

# rubocop:disable Metrics/AbcSize

module HeimdallTools
  class NetsparkerMapper
    def initialize(xml, name=nil, verbose = false)
      @verbose = verbose

      begin
        @cwe_nist_mapping = parse_mapper(CWE_NIST_MAPPING_FILE)
        @owasp_nist_mapping = parse_mapper(OWASP_NIST_MAPPING_FILE)
        data = xml_to_hash(xml)

        @vulnerabilities = data['netsparker-enterprise']['vulnerabilities']['vulnerability']
        @scan_info = data['netsparker-enterprise']['target']

      rescue StandardError => e
        raise "Invalid Netsparker XML file provided Exception: #{e}"
      end

    end


    def to_hdf
      controls = []
      @vulnerabilities.each do |vulnerability|
        @item = {}
        @item['id']                 = vulnerability['LookupId'].to_s
        @item['title']              = vulnerability['name'].to_s
        @item['desc']               = format_control_desc(vulnerability)
        @item['impact']             = impact(vulnerability['severity'])
        @item['tags']               = {}
        @item['descriptions']       = []

        @item['descriptions']       <<  desc_tags(format_check_text(vulnerability), 'check')
        @item['descriptions']       <<  desc_tags(format_fix_text(vulnerability), 'fix')
        @item['refs']               = NA_ARRAY
        @item['source_location']    = NA_HASH
        @item['tags']['nist']       = nist_tag(vulnerability['classification'])
        @item['code']               = ''
        @item['results']            = finding(vulnerability)

        controls << @item
      end
      controls = collapse_duplicates(controls)
      results = HeimdallDataFormat.new(profile_name: 'Netsparker Enterprise Scan',
                                       title: "Netsparker Enterprise Scan ID: #{@scan_info['scan-id']} URL: #{@scan_info['url']}",
                                       summary: "Netsparker Enterprise Scan",
                                       target_id: @scan_info['url'],
                                       controls: controls)
      results.to_hdf
    end

    private

    def parse_html(block)
      block['#cdata-section'].to_s.strip unless block.nil?
    end

    def finding(vulnerability)
      finding = {}
      finding['status'] = 'failed'
      finding['code_desc'] = []
      finding['code_desc'] << "http-request : #{parse_html(vulnerability['http-request']['content']) }"
      finding['code_desc'] << "method : #{vulnerability['http-request']['method']}"
      finding['code_desc'] = finding['code_desc'].join("\n")

      finding['message'] = []
      finding['message'] << "http-response : #{parse_html(vulnerability['http-response']['content']) }"
      finding['message'] << "duration : #{vulnerability['http-response']['duration']}"
      finding['message'] << "status-code : #{vulnerability['http-response']['status-code']}"
      finding['message'] = finding['message'].join("\n")
      finding['run_time'] = NA_FLOAT

      finding['start_time'] =  @scan_info['initiated']
      [finding]
    end

    def format_control_desc(vulnerability)
      text = []
      text << "#{parse_html(vulnerability['description'])}" unless vulnerability['description'].nil?
      text << "Exploitation-skills: #{parse_html(vulnerability['exploitation-skills'])}"  unless vulnerability['exploitation-skills'].nil?
      text << "Extra-information: #{vulnerability['extra-information']}" unless vulnerability['extra-information'].nil?
      text << "Classification: #{vulnerability['classification']}" unless vulnerability['classification'].nil?
      text << "Impact: #{parse_html(vulnerability['impact'])}" unless vulnerability['impact'].nil?
      text << "FirstSeenDate: #{vulnerability['FirstSeenDate']}" unless vulnerability['FirstSeenDate'].nil?
      text << "LastSeenDate: #{vulnerability['LastSeenDate']}" unless vulnerability['LastSeenDate'].nil?
      text << "Certainty: #{vulnerability['certainty']}" unless vulnerability['certainty'].nil?
      text << "Type: #{vulnerability['type']}" unless vulnerability['type'].nil?
      text << "Confirmed: #{vulnerability['confirmed']}" unless vulnerability['confirmed'].nil?
      text.join("<br>")
    end

    def format_check_text(vulnerability)
      text = []
      text << "Exploitation-skills: #{parse_html(vulnerability['exploitation-skills'])}" unless vulnerability['exploitation-skills'].nil?
      text << "Proof-of-concept: #{parse_html(vulnerability['proof-of-concept'])}" unless vulnerability['proof-of-concept'].nil?
      text.join("<br>")
    end

    def format_fix_text(vulnerability)
      text = []
      text << "Remedial-actions: #{parse_html(vulnerability['remedial-actions'])}" unless vulnerability['remedial-actions'].nil?
      text << "Remedial-procedure: #{parse_html(vulnerability['remedial-procedure'])}" unless vulnerability['remedial-procedure'].nil?
      text << "Remedy-references: #{parse_html(vulnerability['remedy-references'])}" unless vulnerability['remedy-references'].nil?
      text.join("<br>")
    end

    def nist_tag(classification)
      tags = []
      entries = @cwe_nist_mapping.select { |x| classification['cwe'].include?(x[:cweid].to_s) && !x[:nistid].nil? }
      tags << entries.map { |x| x[:nistid] }
      entries = @owasp_nist_mapping.select { |x| classification['owasp'].include?(x[:owaspid].to_s) && !x[:nistid].nil? }
      tags << entries.map { |x| x[:nistid] }
      tags.flatten.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def impact(severity)
      IMPACT_MAPPING[severity.to_sym]
    end

    def parse_mapper(mapping_file)
      csv_data = CSV.read(mapping_file, { encoding: 'UTF-8',
                                                   headers: true,
                                                   header_converters: :symbol,
                                                   converters: :all })
      csv_data.map(&:to_hash)
    end

    def desc_tags(data, label)
      { "data": data || NA_STRING, "label": label || NA_STRING }
    end

    # Netsparker report could have multiple issue entries for multiple findings of same issue type.
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
