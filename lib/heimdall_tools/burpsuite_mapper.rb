require 'json'
require 'csv'
require 'heimdall_tools/hdf'
require 'utilities/xml_to_hash'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

CWE_NIST_MAPPING_FILE = File.join(RESOURCE_DIR, 'cwe-nist-mapping.csv')

IMPACT_MAPPING = {
  High: 0.7,
  Medium: 0.5,
  Low: 0.3,
  Information: 0.3
}.freeze

CWE_REGEX = 'CWE-(\d*):'.freeze

DEFAULT_NIST_TAG = ["SA-11", "RA-5", "Rev_4"].freeze

# rubocop:disable Metrics/AbcSize

module HeimdallTools
  class BurpSuiteMapper
    def initialize(burps_xml, name=nil, verbose = false)
      @burps_xml = burps_xml
      @verbose = verbose

      begin
        @cwe_nist_mapping = parse_mapper
        data = xml_to_hash(burps_xml)

        @issues = data['issues']['issue']
        @burpVersion = data['issues']['burpVersion']
        @timestamp = data['issues']['exportTime']

      rescue StandardError => e
        raise "Invalid Burpsuite XML file provided Exception: #{e}"
      end

    end

    def parse_html(block)
      Nokogiri::HTML(block['#cdata-section']).text.to_s.strip unless block.nil?
    end

    def finding(issue)
      finding = {}
      finding['status'] = 'failed'
      finding['code_desc'] = format_code_desc(issue)
      finding['run_time'] = NA_FLOAT
      finding['start_time'] = @timestamp
      [finding]
    end

    def format_code_desc(issue)
      desc = ''
      desc += "Host: ip: #{issue['host']['ip']}, url: #{issue['host']['text']}\n"
      desc += "Location: #{parse_html(issue['location'])}\n"
      desc += "issueDetail: #{parse_html(issue['issueDetail'])}\n" unless issue['issueDetail'].nil?
      desc += "confidence: #{issue['confidence']}\n" unless issue['confidence'].nil?
      desc
    end

    def nist_tag(cweid)
      entries = @cwe_nist_mapping.select { |x| cweid.include?(x[:cweid].to_s) && !x[:nistid].nil? }
      tags = entries.map { |x| [x[:nistid], "Rev_#{x[:rev]}"] }
      tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def parse_cwe(text)
      reg = Regexp.new(CWE_REGEX, Regexp::IGNORECASE)
      text.scan(reg).map(&:first)
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

    # Burpsuite report could have multiple issue entries for multiple findings of same issue type.
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
      @issues.each do |issue|
        @item = {}
        @item['id']                 = issue['type'].to_s
        @item['title']              = parse_html(issue['name'])
        @item['desc']               = parse_html(issue['issueBackground'])
        @item['impact']             = impact(issue['severity'])
        @item['tags']               = {}
        @item['descriptions']       = []
        @item['descriptions']       <<  desc_tags(parse_html(issue['issueBackground']), 'check')
        @item['descriptions']       <<  desc_tags(parse_html(issue['remediationBackground']), 'fix')
        @item['refs']               = NA_ARRAY
        @item['source_location']    = NA_HASH
        @item['tags']['nist']       = nist_tag(parse_cwe(parse_html(issue['vulnerabilityClassifications'])))
        @item['tags']['cweid']      = parse_html(issue['vulnerabilityClassifications'])
        @item['tags']['confidence'] = issue['confidence'].to_s
        @item['code']               = ''
        @item['results']            = finding(issue)

        controls << @item
      end
      controls = collapse_duplicates(controls)
      results = HeimdallDataFormat.new(profile_name: 'BurpSuite Pro Scan',
                                       version: @burpVersion,
                                       title: "BurpSuite Pro Scan",
                                       summary: "BurpSuite Pro Scan",
                                       controls: controls)
      results.to_hdf
    end
  end
end
