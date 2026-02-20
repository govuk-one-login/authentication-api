# API Gateway

This module provisions an OpenAPI-configured API gateway (as opposed to a piecemeal endpoint-by-endpoint one).

Although it can be used directly, it's best to use either [private-api-gateway](../private-api-gateway/) or [public-api-gateway](../public-api-gateway/), depending on the specific flavour of gateway required.

This module is intended to be used alongside multiple [endpoint-lambdas](../endpoint-lambda/), in order to build up an API gateway via a templated OpenAPI spec.

<!-- prettier-ignore-start -->
<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.8 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.75.1 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.75.1 |

## Resources

| Name | Type |
|------|------|
| [aws_api_gateway_deployment.deployment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_deployment) | resource |
| [aws_api_gateway_method_settings.logging_settings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings) | resource |
| [aws_api_gateway_rest_api.rest_api](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_rest_api) | resource |
| [aws_api_gateway_rest_api_policy.rest_api_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_rest_api_policy) | resource |
| [aws_api_gateway_stage.stage](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage) | resource |
| [aws_api_gateway_usage_plan.api_usage_plan](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_usage_plan) | resource |
| [aws_cloudwatch_log_group.access_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.execution_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_group.waf_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_subscription_filter.execution_log_subscription](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_subscription_filter) | resource |
| [aws_cloudwatch_log_subscription_filter.stage_access_log_subscription](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_subscription_filter) | resource |
| [aws_cloudwatch_log_subscription_filter.waf_log_subscription](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_subscription_filter) | resource |
| [aws_wafv2_web_acl_association.waf_association](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_association) | resource |
| [aws_wafv2_web_acl_logging_configuration.waf_logging_configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_logging_configuration) | resource |
| [aws_iam_policy_document.rest_api_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

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
| <a name="input_extra_tags"></a> [extra\_tags](#input\_extra\_tags) | Additional tags to apply to created resources, in addition to the default tags from the provider. This is unlikely to be needed in most cases. | `map(string)` | `{}` | no |
| <a name="input_vpc_endpoint_ids"></a> [vpc\_endpoint\_ids](#input\_vpc\_endpoint\_ids) | The VPC endpoint IDs | `list(string)` | `[]` | no |
| <a name="input_waf_arns"></a> [waf\_arns](#input\_waf\_arns) | The ARNs of any WAFs to attach to the API Gateway | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_api_gateway_execution_arn"></a> [api\_gateway\_execution\_arn](#output\_api\_gateway\_execution\_arn) | n/a |
| <a name="output_api_gateway_id"></a> [api\_gateway\_id](#output\_api\_gateway\_id) | n/a |
| <a name="output_api_gateway_name"></a> [api\_gateway\_name](#output\_api\_gateway\_name) | n/a |
| <a name="output_aws_api_gateway"></a> [aws\_api\_gateway](#output\_aws\_api\_gateway) | n/a |
| <a name="output_aws_api_gateway_stage"></a> [aws\_api\_gateway\_stage](#output\_aws\_api\_gateway\_stage) | n/a |
<!-- END_TF_DOCS -->
<!-- prettier-ignore-end -->
