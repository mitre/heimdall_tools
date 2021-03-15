# Heimdall Tools

![Overall Status](https://github.com/mitre/heimdall_tools/workflows/heimdall_tools/badge.svg)
![Heimdall Tools Build](https://github.com/mitre/heimdall_tools/workflows/Build%20and%20release%20gem/badge.svg)

HeimdallTools supplies several methods to convert output from various tools to "Heimdall Data Format"(HDF) format to be viewable in Heimdall. The current converters are:

- **sonarqube_mapper** - open-source static code analysis tool
- **fortify_mapper** - commercial static code analysis tool
- **zap_mapper** - OWASP ZAP - open-source dynamic code analysis tool
- **burpsuite_mapper** - commercial dynamic analysis tool
- **nessus_mapper** - commercial vulnerability scanner
- **snyk_mapper** - commercial package vulnerability scanner
- **nikto_mapper** - open-source web server scanner 
- **jfrog_xray_mapper** - package vulnerability scanner
- **dbprotect_mapper** - database vulnerability scanner
- **aws_config_mapper** - assess, audit, and evaluate AWS resources
- **netsparker_mapper** - web application security scanner

Ruby 2.4 or higher (check using "ruby -v")

If installation of Ruby is required, perform these steps:

## Linux Installation of Ruby

### Installation on RHEL-based systems

To install Ruby using RVM (Ruby Version Manager):

`sudo yum install curl gpg gcc gcc-c++ make patch autoconf automake bison libffi-devel libtool patch readline-devel sqlite-devel zlib-devel openssl-devel`

`sudo gpg --keyserver hkp://keys.gnupg.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB`

`curl -sSL https://get.rvm.io | bash -s stable`

`source ~/.rvm/scripts/rvm`

Finally, install the latest version of Ruby (stable), currently 2.6.x:

`rvm install 2.6`

`rvm use 2.6 --default`

Verify the installed version number:

`ruby -v`

`ruby 2.6.5p114 (2019-10-01 revision 67812) [x86_64-linux]`

### Installation on Ubuntu-based systems

<https://github.com/rvm/ubuntu_rvm>

# Installation of Heimdall Tools:

`gem install heimdall_tools`

## Command line Usage

On the Command Line, `heimdall_tools help` will print a listing of all the command with a short description.
For detailed help on any command, run `heimdall_tools help [COMMAND]`. Help can also be called with the `-h, --help` flags after any command, like `heimdall_tools fortify_mapper -h`.

For Docker usage, replace the `heimdall_tools` command with the correct Docker command below for your operating system:

- **On Linux and Mac:** `docker run -it -v$(pwd):/share mitre/heimdall_tools`
- **On Windows CMD:** `docker run -it -v%cd%:/share mitre/heimdall_tools`

Note that all of the above Docker commands will mount your current directory on the Docker container. Ensure that you have navigated to the directory you intend to convert files in before executing the command.

## sonarqube_mapper

sonarqube_mapper pulls SonarQube results, for the specified project, from the API and outputs in HDF format Json to be viewed on Heimdall

```
USAGE: heimdall_tools sonarqube_mapper [OPTIONS] -n <project-name> -u <api-url> -o <scan-results.json>

FLAGS:
    -n --name <project-key>         : Project Key of the project in SonarQube
    -u --api_url <api-url>           : url of the SonarQube Server API. Typically ends with /api.
    --auth <credentials>              : username:password or token [optional].
    -o --output <scan-results>       : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example:

heimdall_tools sonarqube_mapper -n sonar_project_key -u http://sonar:9000/api -o scan_results.json

heimdall_tools sonarqube_mapper -n sonar_project_key -u http://sonar:9000/api --auth admin:admin -o scan_results.json
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

## burpsuite_mapper

burpsuite_mapper translates an BurpSuite Pro exported XML results file into HDF format json to be viewable in Heimdall

```
USAGE: heimdall_tools burpsuite_mapper [OPTIONS] -x <burpsuite-xml> -o <scan-results.json>

FLAGS:
    -x <burpsuite_xml>               : path to BurpSuitePro exported XML results file.
    -o --output <scan-results>       : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example: heimdall_tools burpsuite_mapper -x burpsuite_results.xml -o scan_results.json
```

## nessus_mapper

nessus_mapper translates a Nessus-exported XML results file into HDF format json to be viewable in Heimdall

Note: A separate HDF JSON file is generated for each host reported in the Nessus Report.

```
USAGE: heimdall_tools nessus_mapper [OPTIONS] -x <nessus-results-xml> -o <hdf-file-prefix>

FLAGS:
    -x <nessus-results-xml>          : path to Nessus-exported XML results file.
    -o --output_prefix <prefix>      : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example: heimdall_tools nessus_mapper -x nessus-results.xml -o test-env
```

## snyk_mapper

snyk_mapper translates an Snyk results JSON file into HDF format json to be viewable in Heimdall
  
Note: A separate HDF JSON is generated for each project reported in the Snyk Report.

```
USAGE: heimdall_tools snyk_mapper [OPTIONS] -x <snyk-results-json> -o <hdf-file-prefix>

FLAGS:
    -j <snyk_results_jsonl>          : path to Snyk results JSON file.
    -o --output_prefix <prefix>      : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example: heimdall_tools snyk_mapper -j snyk_results.json -o output-file-prefix
```

## nikto_mapper

nikto_mapper translates an Nikto results JSON file into HDF format JSON to be viewable in Heimdall
  
Note: Current this mapper only support single target Nikto Scans.

```
USAGE: heimdall_tools nikto_mapper [OPTIONS] -x <nikto-results-json> -o <hdf-scan-results.json>

FLAGS:
    -j <nikto_results_json>          : path to Nikto results JSON file.
    -o --output_prefix <prefix>      : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example: heimdall_tools nikto_mapper -j nikto_results.json -o nikto_results.json
```

## jfrog_xray_mapper

jfrog_xray_mapper translates an JFrog Xray results JSON file into HDF format JSON to be viewable in Heimdall
  
```
USAGE: heimdall_tools jfrog_xray_mapper [OPTIONS] -j <xray-results-json> -o <hdf-scan-results.json>

FLAGS:
    -j <xray_results_json>           : path to xray results JSON file.
    -o --output <scan-results>       : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example: heimdall_tools jfrog_xray_mapper -j xray_results.json -o xray_results_hdf.json
```

## dbprotect_mapper

dbprotect_mapper translates DBProtect report in `Check Results Details` format XML to HDF format JSON be viewed on Heimdall.
  
```
USAGE: heimdall_tools dbprotect_mapper [OPTIONS] -x <check_results_details_report_xml> -o <db_protect_hdf.json>

FLAGS:
    -x <check_results_details_report_xml>           : path to DBProtect report XML file.
    -o --output <scan-results>       : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example: heimdall_tools dbprotect_mapper -x check_results_details_report.xml -o db_protect_hdf.json
```

## aws_config_mapper

aws_config_mapper pulls Ruby AWS SDK data to translate AWS Config Rule results into HDF format json to be viewable in Heimdall

### AWS Config Rule Mapping:
  The mapping of AWS Config Rules to 800-53 Controls was sourced from [this link](https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist-800-53_rev_4.html).
  
### Authentication with AWS:
  [Developer Guide for configuring Ruby AWS SDK for authentication](https://docs.aws.amazon.com/sdk-for-ruby/v3/developer-guide/setup-config.html)
  
```
USAGE: heimdall_tools aws_config_mapper [OPTIONS] -o <hdf-scan-results.json>

FLAGS:
    -o --output <scan-results>       : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example: heimdall_tools aws_config_mapper -o aws_config_results_hdf.json
```

## netsparker_mapper

netsparker_mapper translates an Netsparker XML results file into HDF format JSON to be viewable in Heimdall.

  The current iteration only works with Netsparker Enterprise Vulnerabilities Scan.

```
USAGE: heimdall_tools netsparker_mapper [OPTIONS] -x <netsparker_results_xml> -o <hdf-scan-results.json>

FLAGS:
    -x <netsparker_results_xml>      : path to netsparker results XML file.
    -o --output <scan-results>       : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example: heimdall_tools netsparker_mapper -x netsparker_results.xml -o netsparker_hdf.json
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

# Publishing a Release

If you are a maintainer, it is very easy to cut a release of this gem:

1. Click on "Releases" and there should be a draft pending.
2. Make sure the Tag version and Release title match!
3. Add any additional notes can be added in the Description box.
4. Click "Publish release".
5. Release notes will be posted and a new gem will be pushed to Rubygems & Github Packages with the version you specified on step 2.

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

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.
