# Endpoint Lambda

This module provisions a lambda from a java zip, and the supporting logging and metrics infrastructure.

This module is designed to be used when a lambda is required, but the API gateway is being configured via some other mechanism,
such as via [endpoint-module-v2](../endpoint-module-v2/).

Eventually, this module will be consumed by [endpoint-module](../endpoint-module/) which currently is a partial clone of this.

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
| <a name="provider_terraform"></a> [terraform](#provider\_terraform) | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_appautoscaling_policy.provisioned-concurrency-policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/appautoscaling_policy) | resource |
| [aws_appautoscaling_target.lambda_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/appautoscaling_target) | resource |
| [aws_cloudwatch_log_group.lambda_log_group](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_metric_filter.lambda_error_metric_filter](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_subscription_filter.log_subscription](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_subscription_filter) | resource |
| [aws_cloudwatch_metric_alarm.lambda_error_cloudwatch_alarm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.lambda_error_rate_cloudwatch_alarm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_lambda_alias.endpoint_lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_alias) | resource |
| [aws_lambda_function.endpoint_lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_provisioned_concurrency_config.endpoint_lambda_concurrency_config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_provisioned_concurrency_config) | resource |
| [terraform_data.wait_for_alias](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_account_alias"></a> [account\_alias](#input\_account\_alias) | The 'friendly-name' of the AWS account, eg. di-auth-development | `string` | n/a | yes |
| <a name="input_cloudwatch_key_arn"></a> [cloudwatch\_key\_arn](#input\_cloudwatch\_key\_arn) | The ARN of the KMS key to use log encryption | `string` | n/a | yes |
| <a name="input_cloudwatch_log_retention"></a> [cloudwatch\_log\_retention](#input\_cloudwatch\_log\_retention) | The number of day to retain Cloudwatch logs for | `number` | n/a | yes |
| <a name="input_dynatrace_secret"></a> [dynatrace\_secret](#input\_dynatrace\_secret) | JSON decoded dynatrace secret | <pre>object({<br/>    JAVA_LAYER = string<br/><br/>    DT_CONNECTION_AUTH_TOKEN     = string<br/>    DT_CONNECTION_BASE_URL       = string<br/>    DT_CLUSTER_ID                = string<br/>    DT_TENANT                    = string<br/>    DT_LOG_COLLECTION_AUTH_TOKEN = string<br/>  })</pre> | n/a | yes |
| <a name="input_endpoint_name"></a> [endpoint\_name](#input\_endpoint\_name) | The name of the endpoint, used for naming resources | `string` | n/a | yes |
| <a name="input_environment"></a> [environment](#input\_environment) | n/a | `string` | n/a | yes |
| <a name="input_handler_environment_variables"></a> [handler\_environment\_variables](#input\_handler\_environment\_variables) | n/a | `map(string)` | n/a | yes |
| <a name="input_handler_function_name"></a> [handler\_function\_name](#input\_handler\_function\_name) | n/a | `string` | n/a | yes |
| <a name="input_lambda_env_vars_encryption_kms_key_arn"></a> [lambda\_env\_vars\_encryption\_kms\_key\_arn](#input\_lambda\_env\_vars\_encryption\_kms\_key\_arn) | n/a | `string` | n/a | yes |
| <a name="input_lambda_role_arn"></a> [lambda\_role\_arn](#input\_lambda\_role\_arn) | n/a | `string` | n/a | yes |
| <a name="input_lambda_zip_file"></a> [lambda\_zip\_file](#input\_lambda\_zip\_file) | n/a | `string` | n/a | yes |
| <a name="input_lambda_zip_file_version"></a> [lambda\_zip\_file\_version](#input\_lambda\_zip\_file\_version) | n/a | `string` | n/a | yes |
| <a name="input_memory_size"></a> [memory\_size](#input\_memory\_size) | n/a | `number` | n/a | yes |
| <a name="input_security_group_ids"></a> [security\_group\_ids](#input\_security\_group\_ids) | The list of security group IDs to apply to the lambda | `list(string)` | n/a | yes |
| <a name="input_slack_event_topic_arn"></a> [slack\_event\_topic\_arn](#input\_slack\_event\_topic\_arn) | The ARN of the slack event topic | `string` | n/a | yes |
| <a name="input_source_bucket"></a> [source\_bucket](#input\_source\_bucket) | n/a | `string` | n/a | yes |
| <a name="input_subnet_id"></a> [subnet\_id](#input\_subnet\_id) | The id of the subnets for the lambda | `list(string)` | n/a | yes |
| <a name="input_architectures"></a> [architectures](#input\_architectures) | n/a | `list(string)` | <pre>[<br/>  "x86_64"<br/>]</pre> | no |
| <a name="input_code_signing_config_arn"></a> [code\_signing\_config\_arn](#input\_code\_signing\_config\_arn) | n/a | `string` | `null` | no |
| <a name="input_endpoint_name_sanitized"></a> [endpoint\_name\_sanitized](#input\_endpoint\_name\_sanitized) | A sanitized version of endpoint\_name, required if endpoint\_name contains a dot. | `string` | `null` | no |
| <a name="input_extra_tags"></a> [extra\_tags](#input\_extra\_tags) | Extra tags to apply to resources | `map(string)` | `{}` | no |
| <a name="input_handler_runtime"></a> [handler\_runtime](#input\_handler\_runtime) | n/a | `string` | `"java17"` | no |
| <a name="input_lambda_error_rate_alarm_disabled"></a> [lambda\_error\_rate\_alarm\_disabled](#input\_lambda\_error\_rate\_alarm\_disabled) | n/a | `bool` | `false` | no |
| <a name="input_lambda_log_alarm_error_rate_threshold"></a> [lambda\_log\_alarm\_error\_rate\_threshold](#input\_lambda\_log\_alarm\_error\_rate\_threshold) | The rate of errors in a lambda before generating a Cloudwatch alarm. Calculated by dividing the number of errors in a lambda divided by the number of invocations in a 60 second period | `number` | `10` | no |
| <a name="input_lambda_log_alarm_threshold"></a> [lambda\_log\_alarm\_threshold](#input\_lambda\_log\_alarm\_threshold) | The number of errors in a lambda logs before generating a Cloudwatch alarm | `number` | `5` | no |
| <a name="input_logging_endpoint_arns"></a> [logging\_endpoint\_arns](#input\_logging\_endpoint\_arns) | Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to | `list(string)` | `[]` | no |
| <a name="input_max_provisioned_concurrency"></a> [max\_provisioned\_concurrency](#input\_max\_provisioned\_concurrency) | n/a | `number` | `5` | no |
| <a name="input_provisioned_concurrency"></a> [provisioned\_concurrency](#input\_provisioned\_concurrency) | n/a | `number` | `0` | no |
| <a name="input_runbook_link"></a> [runbook\_link](#input\_runbook\_link) | A link that is appended to alarm descriptions that should open a page describing how to triage and handle the alarm | `string` | `null` | no |
| <a name="input_scaling_trigger"></a> [scaling\_trigger](#input\_scaling\_trigger) | n/a | `number` | `0.7` | no |
| <a name="input_snapstart"></a> [snapstart](#input\_snapstart) | n/a | `bool` | `false` | no |
| <a name="input_wait_for_alias_timeout"></a> [wait\_for\_alias\_timeout](#input\_wait\_for\_alias\_timeout) | The number of seconds to wait for the alias to be created | `number` | `300` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_endpoint_lambda_alias"></a> [endpoint\_lambda\_alias](#output\_endpoint\_lambda\_alias) | n/a |
| <a name="output_endpoint_lambda_function"></a> [endpoint\_lambda\_function](#output\_endpoint\_lambda\_function) | n/a |
| <a name="output_integration_uri"></a> [integration\_uri](#output\_integration\_uri) | n/a |
| <a name="output_invoke_arn"></a> [invoke\_arn](#output\_invoke\_arn) | n/a |
<!-- END_TF_DOCS -->
<!-- prettier-ignore-end -->
