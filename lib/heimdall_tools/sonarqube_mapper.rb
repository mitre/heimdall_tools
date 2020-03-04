require 'httparty'
require 'json'
require 'csv'
require 'heimdall_tools/hdf'

MAPPING_FILES = {
  cwe: './lib/data/cwe-nist-mapping.csv'.freeze,
  owasp: './lib/data/owasp-nist-mapping.csv'.freeze
}.freeze

IMPACT_MAPPING = {
  BLOCKER: 1.0,
  CRITICAL: 0.7,
  MAJOR: 0.5,
  MINOR: 0.3,
  INFO: 0.0
}.freeze

def check_response(response)
  raise "API Error: #{response.response}\n#{response.body}" unless response.ok?
end

class SonarQubeApi
  ISSUES_ENDPOINT = '/issues/search'.freeze
  RULES_ENDPOINT = '/rules/search'.freeze
  RULE_ENDPOINT = '/rules/show'.freeze
  SOURCE_ENDPOINT = '/sources/raw'.freeze
  VERSION_ENDPOINT = '/server/version'.freeze

  PAGE_SIZE = 100

  def initialize(api_url, auth=nil)
    @api_url = api_url
    @auth = auth
  end

  def query_api(endpoint, params={})
    creds = {
              username: @auth.split(':')[0],
              password: @auth.split(':')[1]
    } unless @auth.nil?

    response = HTTParty.get(@api_url + endpoint, { query: params, basic_auth: creds })
    check_response response
    puts response
    response
  end

  # Query issues endpoint, get all vulnerabilities
  # This query is based on the url params used by the web project issue view
  def query_issues(project_name)
    issues = []
    params = {
      componentKeys: project_name,
        resolved: 'false',
        types: 'VULNERABILITY',
        ps: PAGE_SIZE,
        p: 1
    }

    loop do # Get all pages
      response = query_api(ISSUES_ENDPOINT, params)
      issues += response['issues']

      if params[:p] * PAGE_SIZE >= response['paging']['total']
        break
      end

      params[:p] += 1
    end

    issues
  end

  # Query rules endpoint to get additional info for 800-53 mapping
  def query_rule(rule)
    params = {
      key: rule
    }
    response = query_api(RULE_ENDPOINT, params)
    response['rule']
  end

  # Query the source endpoint for a code snippet showing a vulnerability
  # SonarQube has 3 relevant source endpoints.
  # The web gui uses sources/list (not in webservices), returns each line w/ html formatting and scm
  # sources/show returns just the source lines, but still w/ html formatting
  # Both of the above allow filtering by line, whereas raw does not.
  # sources/raw returns the entire file
  # We are going to use sources/raw for now so we don't have to deal with the html
  def query_code_snippet(component, start_line, end_line)
    params = {
      key: component
    }
    response = query_api(SOURCE_ENDPOINT, params)
    response.body.split("\n")[start_line..end_line].join("\n")
  end

  # Query the version of the SonarQube server
  def query_version
    response = query_api(VERSION_ENDPOINT)
    response.body
  end
end

module HeimdallTools
  class SonarQubeMapper
    # Fetches the necessary data from the API and builds report
    def initialize(project_name, sonarqube_url, auth=nil)
      @project_name = project_name
      @api = SonarQubeApi.new(sonarqube_url,auth)

      @mappings = load_nist_mappings
      @findings = @api.query_issues(@project_name).map { |x| Finding.new(x, @api) }
      @controls = _get_controls
    end

    # Build an array of Controls based on the SonarQube findings
    def _get_controls
      control_key_to_findings_map = Hash.new { |h, k| h[k] = [] }
      @findings.each { |f| control_key_to_findings_map[f.control_key] << f }
      control_key_to_findings_map.map { |control_key, findings| Control.new(control_key, findings, @api, @mappings) }
    end

    def load_nist_mappings
      mappings = {}
      MAPPING_FILES.each do |mapping_type, path|
        csv_data = CSV.read(path, { encoding: 'UTF-8',
                                            headers: true,
                                            header_converters: :symbol,
                                            converters: :all })
        mappings[mapping_type] = Hash[csv_data.map { |row|
          [row[(mapping_type.to_s.downcase + 'id').to_sym].to_s, [row[:nistid], "Rev_#{row[:rev]}"]]
        }]
      end
      mappings
    end

    # Returns a report in HDF format
    def to_hdf
      results = HeimdallDataFormat.new(profile_name: "SonarQube Scan",
                                       version: @api.query_version,
                                       title: "SonarQube Scan of Project: #{@project_name}",
                                       summary: "SonarQube Scan of Project: #{@project_name}",
                                       controls: @controls.map(&:hdf))
      results.to_hdf
    end
  end
end

class Control
  # CWE and CERT will be stated generically in tags (ie. it just says cwe or cert, not which number)
  # OWASP is stated specifically, ex owasp-a1
  #
  # SonarQube is inconsistent with tags (ex some cwe rules don't have cwe number in desc,) as noted below
  TAG_DATA = {} # NOTE: We count on Ruby to preserve order for TAG_DATA
  TAG_DATA[:cwe] = {
    # Some rules with cwe tag don't have cwe number in description!
    # Currently only squid:S2658, but it has OWASP tag so we can use that.
    regex: 'cwe.mitre.org/data/definitions/([^\.]*)' # Sometimes the "http://" is not part of the url
  }
  TAG_DATA[:owasp] = {
    # Many (19 currently) owasp have don't cwe (ex. squid:S3355)
  }
  TAG_DATA[:cert] = {
    # Some rules only have cert tag (ex. kotlin:S1313)
    # Some rules with cert tag don't actually have cert in description!
    # Currently only squid:S4434, but it has OWASP tag so we can use that.
    regex: 'CERT,?\n? ([^<]*)\.?<'
  }
  # All sans-tagged rules have CWE number, so no need to map SANS
  # There some tags which we can map directly (ex. denial-of-service)
  # But there are currently no rules with such a tag that don't have a better tag (ex. cwe)
  # So we will be leaving this functionality out until necessary

  # These rules don't have the cert/cwe number in description or have other problems
  # If there is an error with them, ignore it since we know they have problems.
  KNOWN_BAD_RULES = %w{squid:S4434 squid:S2658}.to_set

  # @param [SonarQubeApi] sonar_api
  def initialize(control_key, findings, sonar_api, mappings)
    @key = control_key
    @findings = findings
    @api = sonar_api
    @mappings = mappings

    @data = @api.query_rule(@key)
  end

  # Get specific tags for a given type.
  # ex. for cwe, get the CWE numbers
  # Output: []  # ["cwe-295", ...]
  def _get_parsed_tags(tag_type)
    tag_data = TAG_DATA[tag_type]
    parsed_tags = []

    if tag_data.key? :regex
      # If the tag type has a regex, try to find the specified tag in the description
      # NOTE: Some tag types can have multiple matches, such as cwe
      reg = Regexp.new(tag_data[:regex], Regexp::IGNORECASE)
      parsed_tags += @data['htmlDesc'].scan(reg).map(&:first)

      if parsed_tags.empty? and not KNOWN_BAD_RULES.include? @key
        puts "Error: Rule #{@key}: No regex matches for #{tag_type} tag." if parsed_tags.empty?
      end
    else
      # If the tag type doesn't have a regex, it is specific enough to be mapped directly
      # Ex. Rule with tag owasp-a1 can be mapped directly.
      parsed_tags = @data['sysTags'] & @mappings[tag_type].keys

      if parsed_tags.empty? and not KNOWN_BAD_RULES.include? @key
        puts "Warning: Rule #{@key}: Has #{tag_type} tag but no usable mapping found."
      end
    end

    parsed_tags
  end

  # Returns the a list of the NIST 800-53 control based on the tags
  def get_nist_tags
    # Since we only care about the most important 800-53 control,
    # we check for tags in order of importance/specificity (cwe's, then owasp, etc. Same as order of tag_data)
    # and return a 800-53 control for the first tag we can map
    TAG_DATA.each do |tag_type, _|
      next unless @data['sysTags'].any? { |tag| tag.start_with? tag_type.to_s }

      parsed_tags = _get_parsed_tags tag_type
      next if parsed_tags.empty?

      parsed_tag = parsed_tags.find { |tag| @mappings[tag_type].key? tag }
      next if parsed_tag.nil?

      return [@mappings[tag_type][parsed_tag]].flatten.uniq
    end

    ['unmapped'] # HDF expects this to be a list, but not an empty list even if there aren't results
  end

  def hdf
    # Note: Structure is based on fortify -> HDF converter output
    {
      title: @data['name'],
        desc: @data['htmlDesc'],
        impact: IMPACT_MAPPING[@data['severity'].to_sym],
        tags: {
          nist: get_nist_tags
        },
        results: @findings.map(&:get_result),
        code: NA_TAG, # This should be the inspec code for the control, which we don't have
        id: @key,
        descriptions: NA_ARRAY,
        refs: NA_ARRAY,
        source_location: NA_HASH,
    }
  end
end

class Finding
  attr_reader :control_key

  # @param [SonarQubeApi] sonar_api
  def initialize(vuln_data, sonar_api)
    @data = vuln_data
    @api = sonar_api

    @key = @data['key']
    @control_key = @data['rule']
    @project = @data['project']
  end

  def get_result
    vuln_start = @data['textRange']['startLine']
    vuln_end =  @data['textRange']['endLine']
    component = @data['component']
    snip_start = [1, vuln_start - 3].max
    snip_end = vuln_end + 3 # api doesn't care if we request lines past end of file
    snip = @api.query_code_snippet(component, snip_start, snip_end)

    snip_html = "StartLine: #{snip_start}, EndLine: #{snip_end}<br>Code:<pre>#{snip}</pre>"
    {
        status: 'failed',
        code_desc: "Path:#{component}:#{vuln_start}:#{vuln_end} #{snip_html}",
        run_time:  NA_FLOAT,
        start_time: Time.now.strftime("%a,%d %b %Y %X")
    }
  end
end

if $PROGRAM_NAME == __FILE__
  puts 'Getting data from SonarQube API'

  url = 'http://sonar:9000/api'
  project_name = 'ansible-test'

  MAPPING_FILES = {
    cwe: '../data/cwe-nist-mapping.csv'.freeze,
      owasp: '../data/owasp-nist-mapping.csv'.freeze
  }.freeze

  sonar_mapper = HeimdallTools::SonarQubeMapper.new(project_name, url)
  File.open('sonarqube_hdf_output.json', 'w') do |f|
    f.write(sonar_mapper.to_hdf)
  end

end
