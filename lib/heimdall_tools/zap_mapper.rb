require 'json'
require 'nokogiri'
require 'csv'
require 'heimdall_tools/hdf'


RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

CWE_NIST_MAPPING_FILE = File.join(RESOURCE_DIR, 'cwe-nist-mapping.csv')
DEFAULT_NIST_TAG = ["SA-11", "RA-5", "Rev_4"].freeze

# rubocop:disable Metrics/AbcSize

module HeimdallTools
  class ZapMapper
    def initialize(zap_json, name, verbose = false)
      @zap_json = zap_json
      @verbose = verbose

      begin
        data = JSON.parse(zap_json, symbolize_names: true)

        unless data[:site].map { |x| x[:@name] }.include?(name)
          abort("Specified site name: #{name} is not defined in the JSON provided.")
        end

        site = data[:site].select { |x| x[:@name].eql?(name) }.first

        @cwe_nist_mapping = parse_mapper
        @zap_verison      = data[:@version]
        @timestamp        = data[:@generated]
        @name             = site[:@name]
        @host             = site[:@host]
        @port             = site[:@port]
        @ssl              = site[:@ssl]
        @alerts           = site[:alerts]
      rescue StandardError => e
        raise "Invalid ZAP results JSON file provided Exception: #{e}"
      end
    end

    def process_instances(instances)
      findings = []
      instances.each do |instance|
        findings << finding(instance)
      end
      findings.uniq
    end

    def finding(instance)
      finding = {}
      finding['status'] = 'failed'
      finding['code_desc'] = format_code_desc(instance)
      finding['run_time'] = NA_FLOAT
      finding['start_time'] = @timestamp
      finding
    end

    def format_code_desc(code_desc)
      desc = ''
      code_desc.keys.each do |key|
        desc += "#{key.capitalize}: #{code_desc[key]}\n"
      end
      desc
    end

    def nist_tag(cweid)
      entries = @cwe_nist_mapping.select { |x| x[:cweid].to_s.eql?(cweid.to_s) }
      tags = entries.map { |x| [x[:nistid], "Rev_#{x[:rev]}"] }
      tags.empty? ? DEFAULT_NIST_TAG : tags.flatten.uniq
    end

    def impact(riskcode)
      if riskcode.to_i.between?(0, 1)
        0.3
      elsif riskcode.to_i == 2
        0.5
      elsif riskcode.to_i >= 3
        0.7
      end
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
      @alerts.each do |alert|
        @item = {}
        @item['id']                 = alert[:pluginid].to_s
        @item['title']              = alert[:name].to_s
        @item['desc']               = Nokogiri::HTML(alert[:desc]).text
        @item['impact']             = impact(alert[:riskcode])
        @item['tags']               = {}
        @item['descriptions']       = NA_ARRAY
        @item['refs']               = NA_ARRAY
        @item['source_location']    = NA_HASH
        @item['tags']['nist']       = nist_tag(alert[:cweid])
        @item['tags']['cweid']      = alert[:cweid].to_s
        @item['tags']['wascid']     = alert[:wascid].to_s
        @item['tags']['sourceid']   = alert[:sourceid].to_s
        @item['tags']['confidence'] = alert[:confidence].to_s
        @item['tags']['riskdesc']   = alert[:riskdesc].to_s
        @item['tags']['check']      = checktext(alert)
        @item['code']               = ''
        @item['results']            = process_instances(alert[:instances])

        controls << @item
      end
      fix_duplicates(controls)

      results = HeimdallDataFormat.new(profile_name: 'OWASP ZAP Scan',
                                       version: @zap_verison,
                                       title: "OWASP ZAP Scan of Host: #{@host}",
                                       summary: "OWASP ZAP Scan of Host: #{@host}",
                                       controls: controls)
      results.to_hdf
    end
  end
end
