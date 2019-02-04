

require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList['test/**/*_test.rb']
end

namespace :test do
  Rake::TestTask.new(:windows) do |t|
    t.libs << 'test'
    t.libs << "lib"
    t.test_files = Dir.glob([
      'test/unit/heimdall_tools/zap_mapper_test.rb',
    ])
  end
end

task :default => :test


