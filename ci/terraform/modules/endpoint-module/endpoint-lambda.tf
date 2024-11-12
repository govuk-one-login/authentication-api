module "endpoint_lambda" {
  source = "../endpoint-lambda"

  endpoint_name                          = var.endpoint_name
  source_bucket                          = var.source_bucket
  lambda_zip_file                        = var.lambda_zip_file
  lambda_zip_file_version                = var.lambda_zip_file_version
  handler_function_name                  = var.handler_function_name
  handler_environment_variables          = var.handler_environment_variables
  handler_runtime                        = var.handler_runtime
  environment                            = var.environment
  authentication_vpc_arn                 = var.authentication_vpc_arn
  security_group_ids                     = var.security_group_ids
  subnet_id                              = var.subnet_id
  lambda_role_arn                        = var.lambda_role_arn
  logging_endpoint_enabled               = var.logging_endpoint_enabled
  logging_endpoint_arn                   = var.logging_endpoint_arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  default_tags                           = var.default_tags
  cloudwatch_key_arn                     = var.cloudwatch_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_log_alarm_threshold             = var.lambda_log_alarm_threshold
  lambda_log_alarm_error_rate_threshold  = var.lambda_log_alarm_error_rate_threshold
  lambda_error_rate_alarm_disabled       = var.lambda_error_rate_alarm_disabled
  lambda_env_vars_encryption_kms_key_arn = var.lambda_env_vars_encryption_kms_key_arn
  code_signing_config_arn                = var.code_signing_config_arn
  memory_size                            = var.memory_size
  provisioned_concurrency                = var.provisioned_concurrency
  max_provisioned_concurrency            = var.max_provisioned_concurrency
  scaling_trigger                        = var.scaling_trigger
  slack_event_topic_arn                  = data.aws_sns_topic.slack_events.arn
  account_alias                          = data.aws_iam_account_alias.current.account_alias
  dynatrace_secret                       = jsondecode(data.aws_secretsmanager_secret_version.dynatrace_secret.secret_string)
}

moved {
  from = aws_lambda_function.endpoint_lambda
  to   = module.endpoint_lambda.aws_lambda_function.endpoint_lambda
}
moved {
  from = aws_cloudwatch_log_group.lambda_log_group[0]
  to   = module.endpoint_lambda.aws_cloudwatch_log_group.lambda_log_group
}
moved {
  from = aws_cloudwatch_log_subscription_filter.log_subscription
  to   = module.endpoint_lambda.aws_cloudwatch_log_subscription_filter.log_subscription
}
moved {
  from = aws_lambda_alias.endpoint_lambda
  to   = module.endpoint_lambda.aws_lambda_alias.endpoint_lambda
}
moved {
  from = aws_lambda_provisioned_concurrency_config.endpoint_lambda_concurrency_config
  to   = module.endpoint_lambda.aws_lambda_provisioned_concurrency_config.endpoint_lambda_concurrency_config
}
moved {
  from = aws_appautoscaling_target.lambda_target
  to   = module.endpoint_lambda.aws_appautoscaling_target.lambda_target
}
moved {
  from = aws_appautoscaling_policy.provisioned-concurrency-policy
  to   = module.endpoint_lambda.aws_appautoscaling_policy.provisioned-concurrency-policy
}
