require 'aws-sdk-configservice'
require 'heimdall_tools/hdf'
require 'csv'
require 'json'

RESOURCE_DIR = Pathname.new(__FILE__).join('../../data')

AWS_CONFIG_MAPPING_FILE = File.join(RESOURCE_DIR, 'aws-config-mapping.csv')

NOT_APPLICABLE_MSG = 'No AWS resources found to evaluate complaince for this rule'.freeze
INSUFFICIENT_DATA_MSG = 'Not enough data has been collectd to determine compliance yet.'.freeze

##
# HDF mapper for use with AWS Config rules.
#
# Ruby AWS Ruby SDK for ConfigService: 
# - https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/ConfigService/Client.html
#
# rubocop:disable Metrics/AbcSize, Metrics/ClassLength
module HeimdallTools
  class AwsConfigMapper
    def initialize(custom_mapping, verbose = false)
      @verbose = verbose
      @default_mapping = get_rule_mapping(AWS_CONFIG_MAPPING_FILE)
      @custom_mapping = custom_mapping.nil? ? {} : get_rule_mapping(custom_mapping)
      @client = Aws::ConfigService::Client.new
      @issues = get_all_config_rules
    end

    ##
    # Convert to HDF
    #
    # If there is overlap in rule names from @default_mapping and @custom_mapping,
    # then the tags from both will be added to the rule.
    def to_hdf
      controls = @issues.map do |issue|
        @item = {}
        @item['id']              = issue[:config_rule_name]
        @item['title']           = issue[:config_rule_name]
        @item['desc']            = issue[:description]
        @item['impact']          = 0.5
        @item['tags']            = hdf_tags(issue)
        @item['descriptions']    = hdf_descriptions(issue)
        @item['refs']            = NA_ARRAY
        @item['source_location'] = { ref: issue[:config_rule_arn], line: 1 }
        @item['code']            = ''
        @item['results']         = issue[:results]
        # Avoid duplicating rules that exist in the custom mapping as 'unmapped' in this loop
        if @custom_mapping.include?(issue[:config_rule_name]) && !@default_mapping.include?(issue[:config_rule_name])
          nil
        else
          @item
        end
      end
      results = HeimdallDataFormat.new(
        profile_name: 'AWS Config',
         title: 'AWS Config',
         summary: 'AWS Config',
         controls: controls,
         statistics: { aws_config_sdk_version: Aws::ConfigService::GEM_VERSION }
        )
      results.to_hdf
    end

    private

    ##
    # Read in a config rule -> 800-53 control mapping CSV.
    #
    # Params: 
    # - path: The file path to the CSV file
    #
    # Returns: A mapped version of the csv in the format { rule_name: row, ... }
    def get_rule_mapping(path)
      Hash[CSV.read(path, headers: true).map { |row| [row[0], row] }]
    end

    ##
    # Fetches information on all of the config rules available to the
    # AWS account.
    #
    # https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/ConfigService/Client.html#describe_config_rules-instance_method
    #
    # Returns: list of hash for all config rules available
    def get_all_config_rules
      config_rules = []

      # Fetch all rules with pagination
      response = @client.describe_config_rules
      config_rules += response.config_rules
      while response.next_token
        response = @client.describe_config_rules(next_token: response.next_token)
        config_rules += response.config_rules
      end
      config_rules = config_rules.map(&:to_h)

      # Add necessary data to rules using helpers
      add_compliance_to_config_rules(config_rules)
      add_results_to_config_rules(config_rules)
    end

    ##
    # Adds compliance information for config rules to the config rule hash
    # from AwsConfigMapper::get_all_config_rules.
    #
    # `complaince_type` may be any of the following:
    # ["COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE", "INSUFFICIENT_DATA"]
    #
    # Params:
    # - config_rules: The list of hash from AwsConfigMapper::get_all_config_rules
    #
    # Returns: The same config_rules array with `compliance` key added to each rule
    def add_compliance_to_config_rules(config_rules)
      mapped_compliance_results = fetch_all_compliance_info(config_rules)

      # Add compliance to config_rules
      config_rules.each do |rule|
        rule[:compliance] = mapped_compliance_results[rule[:config_rule_name]]&.dig(:compliance, :compliance_type)
      end

      config_rules
    end

    ##
    # Fetch and combine all compliance information for the config rules.
    #
    # AWS allows passing up to 25 rules at a time to this endpoint.
    #
    # https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/ConfigService/Client.html#describe_compliance_by_config_rule-instance_method
    #
    # Params:
    # - config_rules: The list of hash from AwsConfigMapper::get_all_config_rules
    #
    # Returns: Results mapped by config rule in the format { name: {<response>}, ... }
    def fetch_all_compliance_info(config_rules)
      compliance_results = []

      config_rules.each_slice(25).each do |slice|
        config_rule_names = slice.map { |r| r[:config_rule_name] }
        response = @client.describe_compliance_by_config_rule(config_rule_names: config_rule_names)
        compliance_results += response.compliance_by_config_rules
      end

      # Map based on name for easy lookup
      Hash[compliance_results.collect { |r| [r.config_rule_name, r.to_h] }]
    end

    ##
    # Takes in config rules and formats the results for hdf format.
    #
    # https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/ConfigService/Client.html#get_compliance_details_by_config_rule-instance_method
    #
    # Example hdf results:
    # [
    #   {
    #     "code_desc": "This rule...",
    #     "run_time": 0.314016,
    #     "start_time": "2018-11-18T20:21:40-05:00",
    #     "status": "passed"
    #   },
    #   ...
    # ]
    #
    # Status may be any of the following: ['passed', 'failed', 'skipped', 'loaded']
    #
    # Params:
    # - rule: Rules from AwsConfigMapper::get_all_config_rules
    #
    # Returns: The same config_rules array with `results` key added to each rule.
    def add_results_to_config_rules(config_rules)
      config_rules.each do |rule|
        response = @client.get_compliance_details_by_config_rule(config_rule_name: rule[:config_rule_name], limit: 100)
        rule_results = response.to_h[:evaluation_results]
        while response.next_token
          response = @client.get_compliance_details_by_config_rule(next_token: response.next_token, limit: 100)
          rule_results += response.to_h[:evaluation_results]
        end

        rule[:results] = []
        rule_results.each do |result|
          hdf_result = {}
          # code_desc
          hdf_result['code_desc'] = result.dig(:evaluation_result_identifier, :evaluation_result_qualifier)&.map do |k, v|
                                      "#{k}: #{v}"
                                    end&.join(', ')
          # start_time
          hdf_result['start_time'] = if result.key?(:config_rule_invoked_time)
                                       DateTime.parse(result[:config_rule_invoked_time].to_s).strftime('%Y-%m-%dT%H:%M:%S%:z')
                                     end
          # run_time
          hdf_result['run_time'] = if result.key?(:result_recorded_time) && result.key?(:config_rule_invoked_time)
                                     (result[:result_recorded_time] - result[:config_rule_invoked_time]).round(6)
                                   end
          # status
          hdf_result['status'] = case result.dig(:compliance_type)
                                 when 'COMPLIANT'
                                   'passed'
                                 when 'NON_COMPLIANT'
                                   'failed'
                                 else
                                   'skipped'
                                 end
          hdf_result['message'] = "(#{hdf_result['code_desc']}): #{result[:annotation] || 'Rule does not pass rule compliance'}" if hdf_result['status'] == 'failed'
          rule[:results] << hdf_result
        end
        next unless rule[:results].empty?

        case rule[:compliance]
        when 'NOT_APPLICABLE'
          rule[:impact] = 0
          rule[:results] << {
            'run_time': 0,
            'code_desc': NOT_APPLICABLE_MSG,
            'skip_message': NOT_APPLICABLE_MSG,
            'start_time': DateTime.now.strftime('%Y-%m-%dT%H:%M:%S%:z'),
            'status': 'skipped'
          }
        when 'INSUFFICIENT_DATA'
          rule[:results] << {
            'run_time': 0,
            'code_desc': INSUFFICIENT_DATA_MSG,
            'skip_message': INSUFFICIENT_DATA_MSG,
            'start_time': DateTime.now.strftime('%Y-%m-%dT%H:%M:%S%:z'),
            'status': 'skipped'
          }
        end
      end

      config_rules
    end

    ##
    # Takes in a config rule and pulls out tags that are useful for HDF.
    #
    # Params:
    # - config_rule: A single config rule from AwsConfigMapper::get_all_config_rules
    #
    # Returns: Hash containing all relevant HDF tags
    def hdf_tags(config_rule)
      result = {}

      @default_mapping
      @custom_mapping

      # NIST tag
      result['nist'] = []
      default_mapping_match = @default_mapping[config_rule[:config_rule_name]]
      
      result['nist'] += default_mapping_match[1].split('|') unless default_mapping_match.nil?

      custom_mapping_match = @custom_mapping[config_rule[:config_rule_name]]
      
      result['nist'] += custom_mapping_match[1].split('|').map { |name| "#{name} (user provided)" } unless custom_mapping_match.nil?

      result['nist'] = ['unmapped'] if result['nist'].empty?

      result
    end

    def check_text(config_rule)
      params = (JSON.parse(config_rule[:input_parameters]).map { |key, value| "#{key}: #{value}" }).join('<br/>')
      check_text = config_rule[:config_rule_arn]
      check_text += "<br/>#{params}" unless params.empty?
      check_text
    end

    ##
    # Takes in a config rule and pulls out information for the descriptions array
    #
    # Params:
    # - config_rule: A single config rule from AwsConfigMapper::get_all_config_rules
    #
    # Returns: Array containing all relevant descriptions information
    def hdf_descriptions(config_rule)
      [
        {
          'label': 'check',
          'data': check_text(config_rule)
        }
      ]
    end
  end
end
# rubocop:enable Metrics/AbcSize, Metrics/ClassLength
