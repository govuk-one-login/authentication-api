# Stack Orchestration Tool

## Setup

Clone the repo https://github.com/govuk-one-login/devplatform-deploy in a directory next to this repo.

### Required CLIs

To run this tool you will need the below CLI's

- aws cli for management of Cloudformation stacks
- jq for formatting and conversion

## How to use

Login into AWS with SSO on the browser. Choose an account, and select `Command line or programmatic access`. In your
terminal, run `aws configure sso` and enter the start URL and region from AWS on your browser. This will create a
profile that you can set as an environment variable, by running `export AWS_PROFILE=<profile>`.

After you have authenticated with the environment you wish to make changes to you can use the `./provision-${env}` script
to make updates to the stacks.

Running the script with no flags or arguments will print out the usage of the script, which will tell you the available
flags and stacks to deploy.

```shell
./provision-dev
> Script to bootstrap di-orchestration-dev account

  Usage:
    $0 [-b|--base-stacks][-p|--pipelines] [-v|--vpc] [-t|--txma]

  Options:
    -l, --list-base-stacks                 Lists the stacks which are deployed as part of the base stacks command
    -b, --base-stacks                      Provision base stacks
    -p, --pipelines                        Provision secure pipelines
    -v, --vpc                              Provision VPC stack
    -t, --txma                             Provision the manual TxMA stack for auditing.
    -c, --cloudwatch-alarm                 Provisions the cloudwatch alarm stack: A stack for deploying an alarm which
                                           monitors the lambda code storage and sends an alert when a threshold is reached.
                                           See confluence page: https://govukverify.atlassian.net/wiki/x/AwCc3Q
```

Each script also has a list base stacks command ( -l/--list-base-stacks ) so it will show you which stacks are considered
part of the "base stacks" for each env.

## How to update

To update the parameters used for our stacks, please update the parameters in
the `configuration/[ENVIRONMENT]/[STACK-NAME]/parameters.json` files.

To update a specific version of a stack, you can bump the version constant at the top of the file and run the update script.
Ensure you check the version bump into main, to ensure the constant defined in the script acts as the source of truth for
the current deployed stack versions.

## Manual stacks

The deployment scripts also support deploying non-dev-platform manual stacks. An example of this is our TxMA auditing
stack (./manual-stacks/txma/template.yml) which is deployed using the local `./local-provisioner.sh` script. This follows
a similar pattern, where we add a `configuration/[ENVIRONMENT]/[STACK-NAME]/parameters.json` and deploy using our `./deploy-${env}`
script.

## SSM Parameters

The following parameters are not provisioned by CloudFormation, and instead are managed manually in Systems Manager Parameter Store:

- `<environment>-ipv-capacity`
- `<environment>-auth-public-encryption-key`
- `<environment>-ipv-public-encryption-key`
