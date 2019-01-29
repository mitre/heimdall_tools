# require_relative '../utilities/' Place any utility code in utilities folder and require here

module HeimdallTools
  class CLI < Command
    desc 'fortify_mapper', 'fortify_mapper translates Fortify fvdl files to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:fortify_mapper)
    option :fvdl, required: true, aliases: '-f'
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def fortify_mapper
      hdf = HeimdallTools::FortifyMapper.new(File.read(options[:fvdl])).to_hdf
      File.write(options[:output], hdf)
    end

    desc 'zap_mapper', 'zap_mapper translates OWASP ZAP results Json to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:fortify_mapper)
    option :json, required: true, aliases: '-j'
    option :name, required: true, aliases: '-n'
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def zap_mapper
      hdf = HeimdallTools::ZapMapper.new(File.read(options[:json]), options[:name]).to_hdf
      File.write(options[:output], hdf)
    end

    desc 'sonarqube_mapper', 'sonarqube_mapper pulls SonarQube results, for the specified project name, from the API and outputs in HDF format Json to be viewed on Heimdall'
    long_desc Help.text(:sonarqube_mapper)
    option :name, required: true, aliases: '-n'
    option :api_url, required: true, aliases: '-u'
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def sonarqube_mapper
      hdf = HeimdallTools::SonarQubeMapper.new(options[:name], options[:api_url]).to_hdf
      File.write(options[:output], hdf)
    end

    desc 'version', 'prints version'
    def version
      puts VERSION
    end
  end
end
