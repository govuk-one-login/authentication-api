# Endpoint Lambda

This module provisions a lambda from a java zip, the supporting logging and metrics infrastructure, and adds an endpoint to an API gateway.

This module is designed to be used when a 'piecemeal' api gateway is being constructed (ie. not via [api-gateway](../api-gateway/)).

Eventually, this module will consume [endpoint-lambda](../endpoint-lambda/), which this is an extension of.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.8 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | 5.75.1 |
| <a name="requirement_local"></a> [local](#requirement\_local) | 2.5.2 |
| <a name="requirement_random"></a> [random](#requirement\_random) | 3.6.3 |
| <a name="requirement_time"></a> [time](#requirement\_time) | 0.12.1 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.45.0 |
| <a name="provider_terraform"></a> [terraform](#provider\_terraform) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_api_gateway_integration.endpoint_integration](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/api_gateway_integration) | resource |
| [aws_api_gateway_method.endpoint_method](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/api_gateway_method) | resource |
| [aws_api_gateway_resource.endpoint_resource](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/api_gateway_resource) | resource |
| [aws_appautoscaling_policy.provisioned-concurrency-policy](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/appautoscaling_policy) | resource |
| [aws_appautoscaling_target.lambda_target](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/appautoscaling_target) | resource |
| [aws_cloudwatch_log_group.lambda_log_group](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_metric_filter.lambda_error_metric_filter](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_subscription_filter.log_subscription](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/cloudwatch_log_subscription_filter) | resource |
| [aws_cloudwatch_metric_alarm.lambda_error_cloudwatch_alarm](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.lambda_error_rate_cloudwatch_alarm](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_lambda_alias.endpoint_lambda](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/lambda_alias) | resource |
| [aws_lambda_function.endpoint_lambda](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/lambda_function) | resource |
| [aws_lambda_permission.endpoint_execution_permission](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/lambda_permission) | resource |
| [aws_lambda_provisioned_concurrency_config.endpoint_lambda_concurrency_config](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/lambda_provisioned_concurrency_config) | resource |
| [terraform_data.wait_for_alias](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |
| [aws_iam_account_alias.current](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/data-sources/iam_account_alias) | data source |
| [aws_secretsmanager_secret.dynatrace_secret](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/data-sources/secretsmanager_secret) | data source |
| [aws_secretsmanager_secret_version.dynatrace_secret](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/data-sources/secretsmanager_secret_version) | data source |
| [aws_sns_topic.slack_events](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/data-sources/sns_topic) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_authentication_vpc_arn"></a> [authentication\_vpc\_arn](#input\_authentication\_vpc\_arn) | n/a | `string` | n/a | yes |
| <a name="input_cloudwatch_key_arn"></a> [cloudwatch\_key\_arn](#input\_cloudwatch\_key\_arn) | The ARN of the KMS key to use log encryption | `string` | n/a | yes |
| <a name="input_endpoint_method"></a> [endpoint\_method](#input\_endpoint\_method) | n/a | `list(string)` | n/a | yes |
| <a name="input_endpoint_name"></a> [endpoint\_name](#input\_endpoint\_name) | n/a | `string` | n/a | yes |
| <a name="input_environment"></a> [environment](#input\_environment) | n/a | `string` | n/a | yes |
| <a name="input_execution_arn"></a> [execution\_arn](#input\_execution\_arn) | n/a | `string` | n/a | yes |
| <a name="input_handler_environment_variables"></a> [handler\_environment\_variables](#input\_handler\_environment\_variables) | n/a | `map(string)` | n/a | yes |
| <a name="input_handler_function_name"></a> [handler\_function\_name](#input\_handler\_function\_name) | n/a | `string` | n/a | yes |
| <a name="input_lambda_env_vars_encryption_kms_key_arn"></a> [lambda\_env\_vars\_encryption\_kms\_key\_arn](#input\_lambda\_env\_vars\_encryption\_kms\_key\_arn) | n/a | `string` | n/a | yes |
| <a name="input_lambda_role_arn"></a> [lambda\_role\_arn](#input\_lambda\_role\_arn) | n/a | `string` | n/a | yes |
| <a name="input_lambda_zip_file"></a> [lambda\_zip\_file](#input\_lambda\_zip\_file) | n/a | `string` | n/a | yes |
| <a name="input_lambda_zip_file_version"></a> [lambda\_zip\_file\_version](#input\_lambda\_zip\_file\_version) | n/a | `string` | n/a | yes |
| <a name="input_memory_size"></a> [memory\_size](#input\_memory\_size) | n/a | `number` | n/a | yes |
| <a name="input_path_part"></a> [path\_part](#input\_path\_part) | n/a | `string` | n/a | yes |
| <a name="input_rest_api_id"></a> [rest\_api\_id](#input\_rest\_api\_id) | n/a | `string` | n/a | yes |
| <a name="input_root_resource_id"></a> [root\_resource\_id](#input\_root\_resource\_id) | n/a | `string` | n/a | yes |
| <a name="input_security_group_ids"></a> [security\_group\_ids](#input\_security\_group\_ids) | The list of security group IDs to apply to the lambda | `list(string)` | n/a | yes |
| <a name="input_source_bucket"></a> [source\_bucket](#input\_source\_bucket) | n/a | `string` | n/a | yes |
| <a name="input_subnet_id"></a> [subnet\_id](#input\_subnet\_id) | The id of the subnets for the lambda | `list(string)` | n/a | yes |
| <a name="input_use_localstack"></a> [use\_localstack](#input\_use\_localstack) | n/a | `bool` | n/a | yes |
| <a name="input_api_key_required"></a> [api\_key\_required](#input\_api\_key\_required) | n/a | `bool` | `false` | no |
| <a name="input_authorizer_id"></a> [authorizer\_id](#input\_authorizer\_id) | n/a | `string` | `null` | no |
| <a name="input_cloudwatch_log_retention"></a> [cloudwatch\_log\_retention](#input\_cloudwatch\_log\_retention) | The number of day to retain Cloudwatch logs for | `number` | `30` | no |
| <a name="input_code_signing_config_arn"></a> [code\_signing\_config\_arn](#input\_code\_signing\_config\_arn) | n/a | `any` | `null` | no |
| <a name="input_create_endpoint"></a> [create\_endpoint](#input\_create\_endpoint) | n/a | `bool` | `true` | no |
| <a name="input_default_tags"></a> [default\_tags](#input\_default\_tags) | Default tags to apply to all resources | `map(string)` | `{}` | no |
| <a name="input_handler_runtime"></a> [handler\_runtime](#input\_handler\_runtime) | n/a | `string` | `"java17"` | no |
| <a name="input_integration_request_parameters"></a> [integration\_request\_parameters](#input\_integration\_request\_parameters) | n/a | `map(string)` | `{}` | no |
| <a name="input_lambda_error_rate_alarm_disabled"></a> [lambda\_error\_rate\_alarm\_disabled](#input\_lambda\_error\_rate\_alarm\_disabled) | n/a | `bool` | `false` | no |
| <a name="input_lambda_log_alarm_error_rate_threshold"></a> [lambda\_log\_alarm\_error\_rate\_threshold](#input\_lambda\_log\_alarm\_error\_rate\_threshold) | The rate of errors in a lambda before generating a Cloudwatch alarm. Calculated by dividing the number of errors in a lambda divided by the number of invocations in a 60 second period | `number` | `10` | no |
| <a name="input_lambda_log_alarm_threshold"></a> [lambda\_log\_alarm\_threshold](#input\_lambda\_log\_alarm\_threshold) | The number of errors in a lambda logs before generating a Cloudwatch alarm | `number` | `5` | no |
| <a name="input_logging_endpoint_arn"></a> [logging\_endpoint\_arn](#input\_logging\_endpoint\_arn) | Amazon Resource Name (ARN) for the endpoint to ship logs to | `string` | `""` | no |
| <a name="input_logging_endpoint_arns"></a> [logging\_endpoint\_arns](#input\_logging\_endpoint\_arns) | Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to | `list(string)` | `[]` | no |
| <a name="input_logging_endpoint_enabled"></a> [logging\_endpoint\_enabled](#input\_logging\_endpoint\_enabled) | Whether the Lambda should ship its logs to the `logging_endpoint_arn` | `bool` | `false` | no |
| <a name="input_max_provisioned_concurrency"></a> [max\_provisioned\_concurrency](#input\_max\_provisioned\_concurrency) | n/a | `number` | `5` | no |
| <a name="input_method_request_parameters"></a> [method\_request\_parameters](#input\_method\_request\_parameters) | n/a | `map(bool)` | `{}` | no |
| <a name="input_provisioned_concurrency"></a> [provisioned\_concurrency](#input\_provisioned\_concurrency) | n/a | `number` | `0` | no |
| <a name="input_runbook_link"></a> [runbook\_link](#input\_runbook\_link) | n/a | `string` | `""` | no |
| <a name="input_scaling_trigger"></a> [scaling\_trigger](#input\_scaling\_trigger) | n/a | `number` | `0.7` | no |
| <a name="input_wait_for_alias_timeout"></a> [wait\_for\_alias\_timeout](#input\_wait\_for\_alias\_timeout) | The number of seconds to wait for the alias to be created | `number` | `300` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_integration_trigger_value"></a> [integration\_trigger\_value](#output\_integration\_trigger\_value) | n/a |
| <a name="output_method_trigger_value"></a> [method\_trigger\_value](#output\_method\_trigger\_value) | n/a |
| <a name="output_resource_id"></a> [resource\_id](#output\_resource\_id) | n/a |
<!-- END_TF_DOCS -->
