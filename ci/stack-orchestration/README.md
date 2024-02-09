# Stack Orchestration Tool

## Setup

Clone the repo https://github.com/govuk-one-login/devplatform-deploy in a directory next to this repo.

### Required CLIs

To run this tool you will need the below CLI's

* aws cli for management of Cloudformation stacks
* jq for formatting and conversion

## How to use

Login into AWS with SSO on the browser. Choose an account, and select `Command line or programmatic access`. In your
terminal, run `aws configure sso` and enter the start URL and region from AWS on your browser. This will create a
profile that you can set as an environment variable, by running `export AWS_PROFILE=<profile>`.

After this you can then run the below, replacing `<environment>`with one
of `sandpit`, `build`, `stage`, `int`, `prod`:

```shell
./provision_all.sh <environment>
```

Note that if you look into the docs for the provisioning script, the parameter we pass `environment` to is actually
called `AWS_ACCOUNT`. Since we aren't using the gds cli, the only place we use this parameter is to label the folders,
which we have done by environment.

## How to update

To update the parameters used for our stacks, please update the parameters in
the `configuration/[ENVIRONMENT]/[PIPELINE]/parameters.json` files.
