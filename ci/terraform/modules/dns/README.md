<!-- prettier-ignore-start -->
<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.8 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | 5.75.1 |
| <a name="requirement_local"></a> [local](#requirement\_local) | 2.5.2 |
| <a name="requirement_random"></a> [random](#requirement\_random) | 3.6.3 |
| <a name="requirement_time"></a> [time](#requirement\_time) | 0.12.1 |
| <a name="requirement_tls"></a> [tls](#requirement\_tls) | 4.0.6 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_terraform"></a> [terraform](#provider\_terraform) | n/a |

## Resources

| Name | Type |
|------|------|
| [terraform_remote_state.dns](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/data-sources/remote_state) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_dns_state_bucket"></a> [dns\_state\_bucket](#input\_dns\_state\_bucket) | n/a | `string` | n/a | yes |
| <a name="input_dns_state_key"></a> [dns\_state\_key](#input\_dns\_state\_key) | n/a | `string` | n/a | yes |
| <a name="input_environment"></a> [environment](#input\_environment) | n/a | `string` | n/a | yes |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | n/a | `string` | `"eu-west-2"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_account_management_api_fqdn"></a> [account\_management\_api\_fqdn](#output\_account\_management\_api\_fqdn) | n/a |
| <a name="output_account_management_api_url"></a> [account\_management\_api\_url](#output\_account\_management\_api\_url) | n/a |
| <a name="output_account_management_fqdn"></a> [account\_management\_fqdn](#output\_account\_management\_fqdn) | n/a |
| <a name="output_account_management_url"></a> [account\_management\_url](#output\_account\_management\_url) | n/a |
| <a name="output_frontend_api_fqdn"></a> [frontend\_api\_fqdn](#output\_frontend\_api\_fqdn) | n/a |
| <a name="output_frontend_api_url"></a> [frontend\_api\_url](#output\_frontend\_api\_url) | n/a |
| <a name="output_frontend_fqdn"></a> [frontend\_fqdn](#output\_frontend\_fqdn) | n/a |
| <a name="output_frontend_url"></a> [frontend\_url](#output\_frontend\_url) | n/a |
| <a name="output_oidc_api_fqdn"></a> [oidc\_api\_fqdn](#output\_oidc\_api\_fqdn) | n/a |
| <a name="output_oidc_api_url"></a> [oidc\_api\_url](#output\_oidc\_api\_url) | n/a |
| <a name="output_service_domain_name"></a> [service\_domain\_name](#output\_service\_domain\_name) | n/a |
<!-- END_TF_DOCS -->
<!-- prettier-ignore-end -->
