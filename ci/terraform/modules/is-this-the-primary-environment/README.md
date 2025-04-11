<!-- prettier-ignore-start -->
<!-- BEGIN_TF_DOCS -->
# Is This The Primary Environment?

This module is used to determine if the environment is the primary environment in the current account:region.
The primary environments are defined in the `primary_environment_names` local variable.
The module will output a boolean value indicating if the environment is a primary environment.

## What is a primary environment?

Primary, in this context, refers to the environment that is deployed first in a given account:region. It is not necessarily the 'most important' one.

## Why this module?

This module is intended to standardize the way we determine if an environment is a primary environment, to ensure consistency across the codebase.
Some resources are only deployed to the primary environment, and this module can be used to conditionally deploy those resources without recreating the check everywhere,
which could lead to inconsistencies.

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.8 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.75.1 |
| <a name="requirement_local"></a> [local](#requirement\_local) | >= 2.5.2 |
| <a name="requirement_random"></a> [random](#requirement\_random) | >= 3.6.3 |
| <a name="requirement_time"></a> [time](#requirement\_time) | >= 0.12.1 |
| <a name="requirement_tls"></a> [tls](#requirement\_tls) | >= 4.0.6 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_environment"></a> [environment](#input\_environment) | The name of the environment | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_is_primary_environment"></a> [is\_primary\_environment](#output\_is\_primary\_environment) | true if this environment is the primary environment in this account:region else false |
| <a name="output_is_primary_environment_with_coresident_dev"></a> [is\_primary\_environment\_with\_coresident\_dev](#output\_is\_primary\_environment\_with\_coresident\_dev) | true if this environment is a primary environment with a coresident dev environment in this account:region else false |
<!-- END_TF_DOCS -->
<!-- prettier-ignore-end -->
