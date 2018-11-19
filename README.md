# WIP - ALPHA

# HeimdallTools

HeimdallTools supplies several CLI tools to convert compliance data for viewing in the Heimdall application stack.

* <add your tools here>

It also includes an API that can be used in a ruby application. The Ruby API is defined in lib/heimdall_tools/...

# Installation

And then execute:

    $ bundle

Clone the repo and install it yourself as:

    $ gem install heimdall_tools

# Usage

## version  

Prints out the gem version

```
USAGE: heimdall_tools version
```

# Development

This gem was developed using the [CLI Template](https://github.com/tongueroo/cli-template), a generator tool that builds a starter CLI project.

There are a set of unit tests. Run `rake test` to run the tests.

To release a new version, update the version number in `version.rb` according to the [Semantic Versioning Policy](https://semver.org/). Then, run `bundle exec rake release` which will create a git tag for the specified version, push git commits and tags, and push the `.gem` file to [github.com](https://github.com/mitre/inspec_tools).

### NOTICE

© 2018 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.
