# coding: utf-8

# rubocop:disable Style/GuardClause

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
begin
  require 'heimdall_tools/version'
rescue LoadError
  nil
end

Gem::Specification.new do |spec| # rubocop:disable Metrics/BlockLength
  spec.name          = 'heimdall_tools'
  spec.version       = HeimdallTools::VERSION rescue "0.0.0.1.ENOGVB"
  spec.authors       = ['Robert Thew', 'Rony Xavier', 'Aaron Lippold']
  spec.email         = ['rxavier@mitre.org']
  spec.summary       = 'Convert Forify, Openzap and Sonarqube results to HDF'
  spec.description   = 'Converter utils that can be included as a gem or used from the command line'
  spec.homepage      = 'https://github.com/mitre/heimdall_tools'
  spec.license       = 'Apache-2.0'

  spec.files         = Dir.glob('{lib,test,exe}/**/*') + %w{Guardfile LICENSE.md Rakefile README.md}
  spec.bindir        = 'exe'
  spec.executables   << 'heimdall_tools'
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'nokogiri', '~> 1.10.9'
  spec.add_runtime_dependency 'thor', '~> 0.19'
  spec.add_runtime_dependency 'json', '~> 2.3'
  spec.add_runtime_dependency 'csv', '~> 3.1'
  spec.add_runtime_dependency 'httparty', '~> 0.18.0'
  spec.add_runtime_dependency 'openssl', '~> 2.1'
  spec.add_runtime_dependency 'nori', '~> 2.6'
  spec.add_runtime_dependency 'git-lite-version-bump', '>= 0.17.2'
  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'minitest', '~> 5.0'
  spec.add_development_dependency 'pry'
  spec.add_development_dependency 'codeclimate-test-reporter'
  spec.add_development_dependency 'rake'
end
