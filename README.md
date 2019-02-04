# WIP - ALPHA

# HeimdallTools

HeimdallTools supplies several CLI tools to convert HDF format to be viewable in Heimdall. The converters in version 1.1.1 are:

* fortify_mapper
* zap_mapper

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

## sonarqube_mapper

sonarqube_mapper pulls SonarQube results, for the specified project, from the API and outputs in HDF format Json to be viewed on Heimdall

```
USAGE: heimdall_tools sonarqube_mapper [OPTIONS] -n <project-name> -u <api-url> -o <scan-results.json>

FLAGS:
    -n --name <project-name>         : name of the project in SonarQube, aka Project Key
    -u --api_url <api-url>           : url of the SonarQube Server API. Typically ends with /api.
    -o --output <scan-results>       : path to output scan-results json.
    -V --verbose                     : verbose run [optional].

example: heimdall_tools sonarqube_mapper -n sonar_project -u http://sonar:9000/api -o scan_results.json
```

## version  

Prints out the gem version

```
USAGE: heimdall_tools version
```

# Development

This gem was developed using the [CLI Template](https://github.com/tongueroo/cli-template), a generator tool that builds a starter CLI project.

There are a set of unit tests. Run `rake test` to run the tests.

To release a new version, update the version number in `version.rb` according to the [Semantic Versioning Policy](https://semver.org/). Then, run `bundle exec rake release` which will create a git tag for the specified version, push git commits and tags, and push the `.gem` file to [github.com](https://github.com/mitre/heimdall_tools).

### NOTICE

© 2018 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.
