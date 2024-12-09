moved {
  from = aws_cloudwatch_log_metric_filter.lambda_error_metric_filter
  to   = module.endpoint_lambda.aws_cloudwatch_log_metric_filter.lambda_error_metric_filter
}

moved {
  from = aws_cloudwatch_metric_alarm.lambda_error_cloudwatch_alarm
  to   = module.endpoint_lambda.aws_cloudwatch_metric_alarm.lambda_error_cloudwatch_alarm
}

moved {
  from = aws_cloudwatch_metric_alarm.lambda_error_rate_cloudwatch_alarm
  to   = module.endpoint_lambda.aws_cloudwatch_metric_alarm.lambda_error_rate_cloudwatch_alarm
}
