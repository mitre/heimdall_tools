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
    option :auth, type: :string, required: false
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def sonarqube_mapper
      hdf = HeimdallTools::SonarQubeMapper.new(options[:name], options[:api_url], options[:auth]).to_hdf
      File.write(options[:output], hdf)
    end

    desc 'burpsuite_mapper', 'burpsuite_mapper translates Burpsuite xml report to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:burpsuite_mapper)
    option :xml, required: true, aliases: '-x'
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def burpsuite_mapper
      hdf = HeimdallTools::BurpSuiteMapper.new(File.read(options[:xml])).to_hdf
      File.write(options[:output], hdf)
    end

    desc 'nessus_mapper', 'nessus_mapper translates nessus xml report to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:nessus_mapper)
    option :xml, required: true, aliases: '-x'
    option :output_prefix, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def nessus_mapper
      hdfs = HeimdallTools::NessusMapper.new(File.read(options[:xml])).to_hdf

      puts "\nHDF Generated:"
      hdfs.keys.each do | host |
        File.write("#{options[:output_prefix]}-#{host}.json", hdfs[host])
        puts "#{options[:output_prefix]}-#{host}.json"
      end
      
    end

    desc 'snyk_mapper', 'snyk_mapper translates Snyk results Json to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:snyk_mapper)
    option :json, required: true, aliases: '-j'
    option :output_prefix, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def snyk_mapper
      hdfs = HeimdallTools::SnykMapper.new(File.read(options[:json]), options[:name]).to_hdf
      puts "\r\HDF Generated:\n"
      hdfs.keys.each do | host |
        File.write("#{options[:output_prefix]}-#{host}.json", hdfs[host])
        puts "#{options[:output_prefix]}-#{host}.json"
      end
    end

    desc 'nikto_mapper', 'nikto_mapper translates Nikto results Json to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:nikto_mapper)
    option :json, required: true, aliases: '-j'
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def nikto_mapper
      hdf = HeimdallTools::NiktoMapper.new(File.read(options[:json])).to_hdf
      File.write(options[:output], hdf)
      puts "\r\HDF Generated:\n"
      puts "#{options[:output]}"
    end

    desc 'jfrog_xray_mapper', 'jfrog_xray_mapper translates Jfrog Xray results Json to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:jfrog_xray_mapper)
    option :json, required: true, aliases: '-j'
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def jfrog_xray_mapper
      hdf = HeimdallTools::JfrogXrayMapper.new(File.read(options[:json])).to_hdf
      File.write(options[:output], hdf)
      puts "\r\HDF Generated:\n"
      puts "#{options[:output]}"
    end
    
    desc 'dbprotect_mapper', 'dbprotect_mapper translates dbprotect results xml to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:dbprotect_mapper)
    option :xml, required: true, aliases: '-x'
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def dbprotect_mapper
      hdf = HeimdallTools::DBProtectMapper.new(File.read(options[:xml])).to_hdf
      File.write(options[:output], hdf)
      puts "\r\HDF Generated:\n"
      puts "#{options[:output]}"
    end

    desc 'aws_config_mapper', 'aws_config_mapper pulls Ruby AWS SDK data to translate AWS Config Rule results into HDF format Json to be viewable in Heimdall'
    long_desc Help.text(:aws_config_mapper)
    # option :custom_mapping, required: false, aliases: '-m'
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def aws_config_mapper
      hdf = HeimdallTools::AwsConfigMapper.new(options[:custom_mapping]).to_hdf
      File.write(options[:output], hdf)
      puts "\r\HDF Generated:\n"
      puts "#{options[:output]}"
    end
    
    desc 'netsparker_mapper', 'netsparker_mapper translates netsparker enterprise results xml to HDF format Json be viewed on Heimdall'
    long_desc Help.text(:netsparker_mapper)
    option :xml, required: true, aliases: '-x'
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def netsparker_mapper
      hdf = HeimdallTools::NetsparkerMapper.new(File.read(options[:xml])).to_hdf
      File.write(options[:output], hdf)
      puts "\r\HDF Generated:\n"
      puts "#{options[:output]}"
    end

    desc 'version', 'prints version'
    def version
      puts VERSION
    end
  end
end
