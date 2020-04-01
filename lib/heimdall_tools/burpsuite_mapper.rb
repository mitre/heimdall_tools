require 'json'
require 'nokogiri'
require 'csv'
require 'heimdall_tools/hdf'
require 'utilities/xml_to_hash'



CWE_NIST_MAPPING_FILE = './lib/data/cwe-nist-mapping.csv'.freeze

IMPACT_MAPPING = {
  High: 0.7,
  Medium: 0.5,
  Low: 0.3,
  Information: 0.0
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
        raise "Invalid Fortify FVDL file provided Exception: #{e}"
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
      finding['start_time'] = "Thu,26 Sep 2019 10:56:37"
      [finding]
    end

    def format_code_desc(issue)
      desc = ''
      desc += "Host: ip: #{issue['host']['ip']}, url: #{issue['host']['text']}\n"
      desc += "Location: #{parse_html(issue['location'])}\n"
      desc += "issueDetail: #{parse_html(issue['issueDetail'])}\n"
      desc
    end

    def nist_tag(cweid)
      entries = @cwe_nist_mapping.select { |x| cweid.include? x[:cweid].to_s }
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

    def checktext(alert)
      [alert[:solution], alert[:otherinfo], alert[:otherinfo]].join("\n")
    end

    def parse_mapper
      csv_data = CSV.read(CWE_NIST_MAPPING_FILE, { encoding: 'UTF-8',
                                                   headers: true,
                                                   header_converters: :symbol,
                                                   converters: :all })
      csv_data.map(&:to_hash)
    end

    def desc_tags(data, label)
      { "data": data, "label": label }
    end

    def fix_duplicates(controls)
      control_ids = controls.map { |x| x['id'] }
      dup_ids = control_ids.select { |x| control_ids.count(x) > 1 }.uniq
      dup_ids.each do |dup_id|
        index = 1
        controls.select { |x| x['id'].eql?(dup_id) }.each do |control|
          control['id'] = control['id'] + '.' + index.to_s
          index += 1
        end
      end
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
      fix_duplicates(controls)
      results = HeimdallDataFormat.new(profile_name: 'BurpSuite Pro Scan',
                                       version: @burpVersion,
                                       title: "BurpSuite Pro Scan",
                                       summary: "BurpSuite Pro Scan",
                                       controls: controls)
      results.to_hdf
    end
  end
end
