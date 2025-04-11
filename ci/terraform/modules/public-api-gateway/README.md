# Public API Gateway

Similar to [private-api-gateway](../private-api-gateway/), this is a wrapper for [api-gateway](../api-gateway/), but this will also provision a domain mapping, which allows the gateway to be routable from the public internet.

<!-- prettier-ignore-start -->
<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.8 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.75.1 |
| <a name="requirement_local"></a> [local](#requirement\_local) | >= 2.5.2 |
| <a name="requirement_random"></a> [random](#requirement\_random) | >= 3.6.3 |
| <a name="requirement_time"></a> [time](#requirement\_time) | >= 0.12.1 |
| <a name="requirement_tls"></a> [tls](#requirement\_tls) | >= 4.0.6 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.75.1 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_api-gateway"></a> [api-gateway](#module\_api-gateway) | ../api-gateway | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_api_gateway_base_path_mapping.api](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_base_path_mapping) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_access_logging_template"></a> [access\_logging\_template](#input\_access\_logging\_template) | The access logging template | `string` | n/a | yes |
| <a name="input_api_gateway_name"></a> [api\_gateway\_name](#input\_api\_gateway\_name) | The name of the API Gateway | `string` | n/a | yes |
| <a name="input_cloudwatch_encryption_key_arn"></a> [cloudwatch\_encryption\_key\_arn](#input\_cloudwatch\_encryption\_key\_arn) | The ARN of the CloudWatch encryption key | `string` | n/a | yes |
| <a name="input_cloudwatch_log_retention"></a> [cloudwatch\_log\_retention](#input\_cloudwatch\_log\_retention) | The retention period for CloudWatch logs | `number` | n/a | yes |
| <a name="input_domain_name"></a> [domain\_name](#input\_domain\_name) | The domain name to bind to the API Gateway | `string` | n/a | yes |
| <a name="input_enable_api_gateway_execution_logging"></a> [enable\_api\_gateway\_execution\_logging](#input\_enable\_api\_gateway\_execution\_logging) | Enable API Gateway execution logging | `bool` | n/a | yes |
| <a name="input_enable_api_gateway_execution_request_tracing"></a> [enable\_api\_gateway\_execution\_request\_tracing](#input\_enable\_api\_gateway\_execution\_request\_tracing) | Enable API Gateway execution request tracing | `bool` | n/a | yes |
| <a name="input_environment"></a> [environment](#input\_environment) | The environment the API Gateway is in | `string` | n/a | yes |
| <a name="input_extra_tags"></a> [extra\_tags](#input\_extra\_tags) | Additional tags to apply to created resources, in addition to the default tags from the provider. This is unlikely to be needed in most cases. | `map(string)` | n/a | yes |
| <a name="input_logging_endpoint_arns"></a> [logging\_endpoint\_arns](#input\_logging\_endpoint\_arns) | The ARNs of the logging endpoints | `list(string)` | n/a | yes |
| <a name="input_openapi_spec"></a> [openapi\_spec](#input\_openapi\_spec) | The content of the OpenAPI spec to deploy | `string` | n/a | yes |
| <a name="input_waf_arns"></a> [waf\_arns](#input\_waf\_arns) | The ARNs of any WAFs to attach to the API Gateway | `list(string)` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_api_gateway_execution_arn"></a> [api\_gateway\_execution\_arn](#output\_api\_gateway\_execution\_arn) | n/a |
| <a name="output_api_gateway_id"></a> [api\_gateway\_id](#output\_api\_gateway\_id) | n/a |
| <a name="output_api_gateway_name"></a> [api\_gateway\_name](#output\_api\_gateway\_name) | n/a |
<!-- END_TF_DOCS -->
<!-- prettier-ignore-end -->
