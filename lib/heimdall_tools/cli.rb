# require_relative '../utilities/' Place any utility code in utilities folder and require here

# rubocop:disable Style/GuardClause

module HeimdallTools
  class CLI < Command
    desc 'fortify_mapper', 'fortify_mapper translates Fortify fvdl files to JSONS be viewed on Heimdall'
    long_desc Help.text(:fortify_mapper)
    option :fvdl, required: true, aliases: '-f'
    option :output, required: true, aliases: '-o'
    option :verbose, type: :boolean, aliases: '-V'
    def fortify_mapper
      hdf = HeimdallTools::FortifyMapper.new(File.read(options[:fvdl])).to_hdf
      File.write(options[:output], hdf)
    end

    desc 'version', 'prints version'
    def version
      puts VERSION
    end
  end
end
