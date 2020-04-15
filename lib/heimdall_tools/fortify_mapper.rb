require 'json'
require 'heimdall_tools/hdf'
require 'utilities/xml_to_hash'

NIST_REFERENCE_NAME = 'Standards Mapping - NIST Special Publication 800-53 Revision 4'.freeze

module HeimdallTools
  class FortifyMapper
    def initialize(fvdl, verbose = false)
      @fvdl = fvdl
      @verbose = verbose

      begin
        data = xml_to_hash(fvdl)
        @timestamp = data['FVDL']['CreatedTS']
        @vulns = data['FVDL']['Vulnerabilities']['Vulnerability']
        @snippets = data['FVDL']['Snippets']['Snippet']
        @rules = data['FVDL']['Description']
        @uuid = data['FVDL']['UUID']
        @fortify_version = data['FVDL']['EngineData']['EngineVersion']

      rescue StandardError => e
        raise "Invalid Fortify FVDL file provided Exception: #{e}"
      end
    end

    def process_entry(entry)
      snippetid = entry['Node']['SourceLocation']['snippet']
      finding = {}
      finding['status'] = 'failed'
      finding['code_desc'] = snippet(snippetid)
      finding['run_time'] = NA_FLOAT
      finding['start_time'] = [@timestamp['date'], @timestamp['time']].join(' ')
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
          # This is just regular array access, it is just written in a manner that allows us
          # to use Ruby's safe navigation operator. We rely on
          # entry['Node']['SourceLocation']['snippet'] to exist on all of our entries, so if any
          # of those are empty we reject that element.
          entries = entries.reject { |x| x&.[]('Node')&.[]('SourceLocation')&.[]('snippet').nil? }
          entries.each do |entry|
            findings << process_entry(entry)
          end
        end
      end
      findings.uniq
    end

    def snippet(snippetid)
      snippet = @snippets.select { |x| x['id'].eql?(snippetid) }.first
      "\nPath: #{snippet['File']}\n" \
      "StartLine: #{snippet['StartLine']}, " \
      "EndLine: #{snippet['EndLine']}\n" \
      "Code:\n#{snippet['Text']['#cdata-section'].strip}" \
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
      controls = []
      @rules.each do |rule|
        @item = {}
        @item['id']              = rule['classID']
        @item['desc']            = rule['Explanation']
        @item['title']           = rule['Abstract']
        @item['impact']          = impact(rule['classID'])
        @item['descriptions']    = NA_ARRAY
        @item['refs']            = NA_ARRAY
        @item['source_location'] = NA_HASH
        @item['code']            = NA_TAG
        @item['results']         = []
        @item['results']         = primaries(@item['id'])
        @item['tags']            = {}
        @item['tags']['nist']    = [nist_tag(rule).to_s, 'Rev_4']
        controls << @item
      end
      results = HeimdallDataFormat.new(profile_name: 'Fortify Static Analyzer Scan',
                                       version: @fortify_version,
                                       title: 'Fortify Static Analyzer Scan',
                                       summary: "Fortify Static Analyzer Scan of UUID: #{@uuid}",
                                       controls: controls)
      results.to_hdf
    end
  end
end
