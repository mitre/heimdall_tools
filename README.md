# Heimdall Tools

![](https://github.com/mitre/heimdall_tools/workflows/heimdall_tools/badge.svg)

HeimdallTools supplies several methods to convert output from various tools to "Heimdall Data Format"(HDF) format to be viewable in Heimdall. The converters in version 1.1.1 are from:

* __sonarqube_mapper__ - open-source static code analysis tool
* __fortify_mapper__ - commercial static code analysis tool
* __zap_mapper__ - OWASP ZAP - open-source dynamic code analysis tool

# Installation

Add this line to your application's Gemfile:

```
gem 'heimdall_tools', :git => "https://github.com/mitre/heimdall_tools"
```

And then execute:

```
    $ bundle
```

Clone the repo and install it yourself as:

```
    $ gem install heimdall_tools
```

## Command line Usage

On the Command Line, `heimdall_tools help` will print a listing of all the command with a short description.
For detailed help on any command, run `heimdall_tools help [COMMAND]`. Help can also be called with the `-h, --help` flags after any command, like `heimdall_tools fortify_mapper -h`.

## sonarqube_mapper

sonarqube_mapper pulls SonarQube results, for the specified project, from the API and outputs in HDF format Json to be viewed on Heimdall

```
USAGE: heimdall_tools sonarqube_mapper [OPTIONS] -n <project-name> -u <api-url> -o <scan-results.json>

FLAGS:
    -n --name <project-name>         : name of the project in SonarQube, aka Project Key
    -u --api_url <api-url>           : url of the SonarQube Server API. Typically ends with /api.
    --auth <credentials>              : username:password or token [optional].
    -o --output <scan-results>       : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example: heimdall_tools sonarqube_mapper -n sonar_project -u http://sonar:9000/api -o scan_results.json

authenticated example: heimdall_tools sonarqube_mapper -n sonar_project -u http://sonar:9000/api --auth admin:admin -o scan_results.json
```

## fortify_mapper

fortify_mapper translates an Fortify results FVDL file into HDF format json to be viewable in Heimdall

```
USAGE: heimdall_tools fortify_mapper [OPTIONS] -f <fortify-fvdl> -o <scan-results.json>

FLAGS:
	-f --fvdl <fortify-fvdl>         : path to Fortify Scan FVDL file.
	-o --output <scan-results>       : path to output scan-results json.
	-V --verbose                     : verbose run [optional].

example: heimdall_tools fortify_mapper -f audit.fvdl -o scan_results.json
```

## zap_mapper

zap_mapper translates OWASP ZAP results Json to HDF format Json be viewed on Heimdall

```
USAGE: heimdall_tools zap_mapper [OPTIONS] -j <zap-json> -n <site-name> -o <scan-results.json>

FLAGS:
    -j --json <zap-json>             : path to OWASP ZAP results JSON file.
    -n --name <site-name>            : URL of the site being evaluated.
    -o --output <scan-results>       : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example: heimdall_tools zap_mapper -j zap_results.json -n site_name -o scan_results.json
```

## version  

Prints out the gem version

```
USAGE: heimdall_tools version
```

# Development

## Submitting a PR  

### A complete PR should include 7 core elements:  

- A signed PR ( aka `git commit -a -s` )
- Code for the new functionality
- Updates to the CLI
- New unit tests for the functionality
- Updates to the docs and examples in `README.md` and `./docs/*`
- (if needed) Example / Template files ( `metadata.yml`,`example.yml`, etc )
  - Scripts / Scaffolding code for the Example / Template files ( `generate_map` is an example )
- Example Output of the new functionality if it produces an artifact

### Overview of our PR process 

1. open an issue on the main inspec_tools website noting the issues your PR will address
2. fork the repo
3. checkout your repo
4. cd to the repo
5. git co -b `<your_branch>`
6. bundle install
7. `hack as you will`
8. test via rake
9. ensure unit tests still function and add unit tests for your new feature
10. add new docs to the `README.md` and to `./docs/examples`
11. update the CLI as needed and add in `usage` example
12. (if needed) create and document any example or templates
13. (if needed) create any supporing scripts
14. (opt) gem build inspec_tools.gemspec
15. (opt) gem install inspec_tools
16. (opt) test via the installed gem
17. git commit -a -s `<your_branch>`
18. Open a PRs aginst the MITRE inspec_tools repo

# Testing

This gem was developed using the [CLI Template](https://github.com/tongueroo/cli-template), a generator tool that builds a starter CLI project.

There are a set of unit tests. Run `rake test` to run the tests.

To release a new version, update the version number in `version.rb` according to the [Semantic Versioning Policy](https://semver.org/). Then, run `bundle exec rake release` which will create a git tag for the specified version, push git commits and tags, and push the `.gem` file to [github.com](https://github.com/mitre/heimdall_tools).


# License and Author

### Authors

- Author:: Rony Xavier [rx294](https://github.com/rx294)
- Author:: Dan Mirsky [mirskiy](https://github.com/mirskiy)

### NOTICE   

© 2018 The MITRE Corporation.  

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.   

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  
