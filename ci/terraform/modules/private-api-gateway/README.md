# Private API Gateway

This module provisions an OpenAPI-based API gateway that does not have a domain mapping.
Functionally, this is a transparent wrapper for [api-gateway](../api-gateway/), but it means that when used,
it's immediately obvious that this provisions a **_private_** gateway (as opposed to a public one).

<!-- prettier-ignore-start -->
<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.8 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_api-gateway"></a> [api-gateway](#module\_api-gateway) | ../api-gateway | n/a |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_access_logging_template"></a> [access\_logging\_template](#input\_access\_logging\_template) | The access logging template | `string` | n/a | yes |
| <a name="input_api_gateway_name"></a> [api\_gateway\_name](#input\_api\_gateway\_name) | The name of the API Gateway | `string` | n/a | yes |
| <a name="input_cloudwatch_encryption_key_arn"></a> [cloudwatch\_encryption\_key\_arn](#input\_cloudwatch\_encryption\_key\_arn) | The ARN of the CloudWatch encryption key | `string` | n/a | yes |
| <a name="input_cloudwatch_log_retention"></a> [cloudwatch\_log\_retention](#input\_cloudwatch\_log\_retention) | The retention period for CloudWatch logs | `number` | n/a | yes |
| <a name="input_enable_api_gateway_execution_logging"></a> [enable\_api\_gateway\_execution\_logging](#input\_enable\_api\_gateway\_execution\_logging) | Enable API Gateway execution logging | `bool` | n/a | yes |
| <a name="input_enable_api_gateway_execution_request_tracing"></a> [enable\_api\_gateway\_execution\_request\_tracing](#input\_enable\_api\_gateway\_execution\_request\_tracing) | Enable API Gateway execution request tracing | `bool` | n/a | yes |
| <a name="input_environment"></a> [environment](#input\_environment) | The environment the API Gateway is in | `string` | n/a | yes |
| <a name="input_logging_endpoint_arns"></a> [logging\_endpoint\_arns](#input\_logging\_endpoint\_arns) | The ARNs of the logging endpoints | `list(string)` | n/a | yes |
| <a name="input_openapi_spec"></a> [openapi\_spec](#input\_openapi\_spec) | The content of the OpenAPI spec to deploy | `string` | n/a | yes |
| <a name="input_vpc_endpoint_ids"></a> [vpc\_endpoint\_ids](#input\_vpc\_endpoint\_ids) | The VPC endpoint IDs | `list(string)` | n/a | yes |
| <a name="input_extra_tags"></a> [extra\_tags](#input\_extra\_tags) | Additional tags to apply to created resources, in addition to the default tags from the provider. This is unlikely to be needed in most cases. | `map(string)` | `{}` | no |
| <a name="input_waf_arns"></a> [waf\_arns](#input\_waf\_arns) | The ARNs of any WAFs to attach to the API Gateway | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_api_gateway_execution_arn"></a> [api\_gateway\_execution\_arn](#output\_api\_gateway\_execution\_arn) | n/a |
| <a name="output_api_gateway_id"></a> [api\_gateway\_id](#output\_api\_gateway\_id) | n/a |
| <a name="output_api_gateway_name"></a> [api\_gateway\_name](#output\_api\_gateway\_name) | n/a |
| <a name="output_api_gateway_stage_name"></a> [api\_gateway\_stage\_name](#output\_api\_gateway\_stage\_name) | n/a |
<!-- END_TF_DOCS -->
<!-- prettier-ignore-end -->
