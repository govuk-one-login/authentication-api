# Cloudfront WAF stack

This script deploys a cloudformation stack in the us-east-1 region which creates a WAF for use with the Cloudfront
distribution for the `oidc.` domain.

## Usage

The parameters for the template should be configured in a file at `<env>/parameters.json`. The tags to apply to created
resources should be configured in a file at `<env>/tags.json`.

The list of permitted environments is set up in the script. The script will automatically log in to the correct AWS
account and then create or update the Cloudformation stack using the parameters and tags provided.

If you have not done so already, your AWS profiles will need to be configured using the
script [here](../../../scripts/export_aws_creds.sh).

Note that the `dev` environment refers to the `oidc.sandpit.account.gov.uk` domain.

### Create stack

```
./deploy.sh <env> --create
```

### Update stack

```
./deploy.sh <env>
```
