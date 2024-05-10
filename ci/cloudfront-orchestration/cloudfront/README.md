# Cloudfront stack

This script deploys a cloudformation stack in the eu-west-2 region which creates a Cloudfront distribution for
the `oidc.` domain.

The template deployed is maintained by the Dev Platform team and can be found
at https://github.com/govuk-one-login/devplatform-deploy/tree/main/cloudfront-distribution

## Usage

The parameters for the template should be configured in a file at `<env>/parameters.json`. The tags to apply to created
resources should be configured in a file at `<env>/tags.json`.

The list of permitted environments is set up in the script. The script will automatically log in to the correct AWS
account and then create or update the Cloudformation stack using the parameters and tags provided.

If you have not done so already, your AWS profiles will need to be configured using the
script [here](../../../scripts/set-up-sso.sh).

Note that the `dev` environment refers to the `oidc.sandpit.account.gov.uk` domain.

### Secret values

The template accepts two secret parameters: `OriginCloakingHeader` and `PreviousOriginCloakingHeader`. These are
configured on the WAF applied to the origin API Gateway to require all traffic comes from this Cloudfront distribution.

The script fetches the value of these parameters from secrets manager using the naming
convention `/deploy/<env>/oidc_origin_cloaking_header` and `/deploy/<env>/previous_oidc_origin_cloaking_header`.
The environment for dev is `sandpit`.

You can override the value from Secrets Manager by setting an environment variable with the
name `ORIGIN_CLOAKING_HEADER` or `PREVIOUS_ORIGIN_CLOAKING_HEADER`.

### Create stack

```
./deploy.sh <env> --create
```

### Update stack

```
./deploy.sh <env>
```
