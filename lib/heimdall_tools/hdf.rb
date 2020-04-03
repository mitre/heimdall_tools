require 'json'
require 'heimdall_tools/version'
require 'openssl'

NA_STRING = "".freeze
NA_TAG = nil.freeze
NA_ARRAY = [].freeze
NA_HASH = {}.freeze
NA_FLOAT = 0.0.freeze

PLATFORM_NAME = 'Heimdall Tools'.freeze


module HeimdallTools
  class HeimdallDataFormat
    def initialize(profile_name: NA_TAG,
                   version: NA_TAG,
                   duration: NA_TAG,
                   sha256: NA_TAG,
                   title: NA_TAG,
                   maintainer: NA_TAG,
                   summary: NA_TAG,
                   license: NA_TAG,
                   copyright: NA_TAG,
                   copyright_email: NA_TAG,
                   supports: NA_ARRAY,
                   attributes: NA_ARRAY,
                   depends: NA_ARRAY,
                   groups: NA_ARRAY,
                   status: 'loaded',
                   controls: NA_TAG)

      @results_json = {}
      @results_json['platform'] = {}
      @results_json['platform']['name'] = 'Heimdall Tools'
      @results_json['platform']['release'] = HeimdallTools::VERSION
      @results_json['version'] = HeimdallTools::VERSION

      @results_json['statistics'] = {}
      @results_json['statistics']['duration'] = duration || NA_TAG

      @results_json['profiles'] = []

      profile_block = {}
      profile_block['name']            = profile_name
      profile_block['version']         = version
      profile_block['title']           = title
      profile_block['maintainer']      = maintainer
      profile_block['summary']         = summary
      profile_block['license']         = license
      profile_block['copyright']       = copyright
      profile_block['copyright_email'] = copyright_email
      profile_block['supports']        = supports
      profile_block['attributes']      = attributes
      profile_block['depends']         = depends
      profile_block['groups']          = groups
      profile_block['status']          = status
      profile_block['controls']        = controls
      profile_block['sha256']          = OpenSSL::Digest::SHA256.digest(profile_block.to_s).unpack("H*")[0]
      @results_json['profiles'] << profile_block
    end

    def to_hdf
      @results_json.to_json
    end
  end
end
