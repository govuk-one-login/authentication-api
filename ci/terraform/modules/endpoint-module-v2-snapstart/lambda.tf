moved {
  from = aws_lambda_function.endpoint_lambda
  to   = module.endpoint_lambda.aws_lambda_function.endpoint_lambda
}

moved {
  from = aws_cloudwatch_log_group.lambda_log_group
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

moved {
  from = terraform_data.wait_for_alias
  to   = module.endpoint_lambda.terraform_data.wait_for_alias
}
