resource "aws_cloudwatch_log_metric_filter" "lambda_error_metric_filter" {
  count          = var.use_localstack ? 0 : 1
  name           = replace("${var.environment}-${var.endpoint_name}-errors", ".", "")
  pattern        = "ERROR"
  log_group_name = aws_cloudwatch_log_group.lambda_log_group[0].name

  metric_transformation {
    name      = replace("${var.environment}-${var.endpoint_name}-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_error_cloudwatch_alarm" {
  count               = var.use_localstack ? 0 : 1
  alarm_name          = replace("${var.environment}-${var.endpoint_name}-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.lambda_error_metric_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.lambda_error_metric_filter[0].metric_transformation[0].namespace
  period              = "3600"
  statistic           = "Sum"
  threshold           = var.lambda_log_alarm_threshold
  alarm_description   = "${var.lambda_log_alarm_threshold} or more errors have occurred in the ${var.environment} ${var.endpoint_name} lambda"
  alarm_actions       = [data.aws_sns_topic.slack_events.arn]
}

data "aws_sns_topic" "slack_events" {
  name = "${var.environment}-slack-events"
}
