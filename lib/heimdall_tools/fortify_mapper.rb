require 'json'
require 'nokogiri'
require 'nori'

NIST_REFERENCE_NAME = 'Standards Mapping - NIST Special Publication 800-53 Revision 4'.freeze

module HeimdallTools
  class FortifyMapper
    def initialize(fvdl, verbose = false)
      @fvdl = fvdl
      @verbose = verbose

      begin
        data = Nori.new(empty_tag_value: true).parse(fvdl)
        @timestamp = data['FVDL']['CreatedTS']
        @vulns = data['FVDL']['Vulnerabilities']['Vulnerability']
        @snippets = data['FVDL']['Snippets']['Snippet']
        @rules = data['FVDL']['Description']
      rescue StandardError => e
        raise "Invalid Fortify FVDL file provided Exception: #{e}"
      end
    end

    def process_entry(entry)
      snippetid = entry['Node']['SourceLocation']['@snippet']
      finding = {}
      finding['status'] = 'failed'
      finding['code_desc'] = snippet(snippetid)
      finding
    end

    def primaries(classid)
      matched_vulns = @vulns.select { |x| x['ClassInfo']['ClassID'].eql?(classid) }
      findings = []
      matched_vulns.each do |vuln|
        traces = vuln['AnalysisInfo']['Unified']['Trace']
        traces = [traces] unless traces.is_a?(Array)
        traces.each do |trace|
          entries = trace['Primary']['Entry']
          entries = [entries] unless entries.is_a?(Array)
          entries = entries.reject { |x| x['Node'].nil? }
          entries.each do |entry|
            findings << process_entry(entry)
          end
        end
      end
      findings.uniq
    end

    def snippet(snippetid)
      snippet = @snippets.select { |x| x['@id'].eql?(snippetid) }.first
      "\nPath: #{snippet['File']}\n" \
      "StartLine: #{snippet['StartLine']}, " \
      "EndLine: #{snippet['EndLine']}\n" \
      "Code:\n#{snippet['Text'].strip}" \
    end

    def nist_tag(rule)
      references = rule['References']['Reference']
      references = [references] unless references.is_a?(Array)
      tag = references.detect { |x| x['Author'].eql?(NIST_REFERENCE_NAME) }
      tag.nil? ? 'unmapped' : tag['Title'].match(/[a-zA-Z][a-zA-Z]-\d{1,2}/)
    end

    def impact(classid)
      vuln = @vulns.detect { |x| x['ClassInfo']['ClassID'].eql?(classid) }
      vuln['ClassInfo']['DefaultSeverity'].to_f / 5
    end

    def to_hdf
      inpsec_json = {}

      inpsec_json['name'] = 'Fortify Static Analyzer Scan'
      inpsec_json['version'] = [@timestamp['@date'], @timestamp['@time']].join(' ')
      inpsec_json['controls'] = []

      @rules.each do |rule|
        @item = {}
        @item['id']           = rule['@classID']
        @item['desc']         = rule['Explanation']
        @item['title']        = rule['Abstract']
        @item['impact']       = impact(rule['@classID'])
        @item['code']         = ''
        @item['results']      = []
        @item['results']      = primaries(@item['id'])
        @item['tags']         = {}
        @item['tags']['nist'] = [nist_tag(rule).to_s, 'Rev_4']
        inpsec_json['controls'] << @item
      end
      inpsec_json.to_json
    end
  end
end
