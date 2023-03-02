data "aws_cloudwatch_log_group" "doc_app_callback_lambda_log_group" {
  count = var.use_localstack ? 0 : 1
  name  = replace("/aws/lambda/${var.environment}-doc-app-callback-lambda", ".", "")

  depends_on = [
    module.doc-app-callback
  ]
}

data "aws_cloudwatch_log_group" "doc_app_authorize_lambda_log_group" {
  count = var.use_localstack ? 0 : 1
  name  = replace("/aws/lambda/${var.environment}-doc-app-authorize-lambda", ".", "")

  depends_on = [
    module.doc-app-authorize
  ]
}

resource "aws_cloudwatch_log_metric_filter" "doc_app_callback_metric_filter" {
  count          = var.use_localstack ? 0 : 1
  name           = replace("${var.environment}-doc-app-callback-p1-errors", ".", "")
  pattern        = "{($.level = \"ERROR\")}"
  log_group_name = data.aws_cloudwatch_log_group.doc_app_callback_lambda_log_group[0].name

  metric_transformation {
    name      = replace("${var.environment}-doc-app-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "doc_app_authorize_metric_filter" {
  count          = var.use_localstack ? 0 : 1
  name           = replace("${var.environment}-doc-app-authorize-p1-errors", ".", "")
  pattern        = "{($.level = \"ERROR\")}"
  log_group_name = data.aws_cloudwatch_log_group.doc_app_authorize_lambda_log_group[0].name

  metric_transformation {
    name      = replace("${var.environment}-doc-app-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "doc_app_p1_cloudwatch_alarm" {
  count               = var.use_localstack ? 0 : 1
  alarm_name          = replace("${var.environment}-P1-doc-app-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.doc_app_authorize_metric_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.doc_app_authorize_metric_filter[0].metric_transformation[0].namespace
  period              = var.doc_app_p1_alarm_error_time_period
  statistic           = "Sum"
  threshold           = var.doc_app_p1_alarm_error_threshold
  alarm_description   = "${var.doc_app_p1_alarm_error_threshold} or more Doc App errors have occurred in ${var.environment}.ACCOUNT: ${data.aws_iam_account_alias.current.account_alias}"
  alarm_actions       = [var.environment == "production" ? data.aws_sns_topic.pagerduty_p1_alerts[0].arn : data.aws_sns_topic.slack_events.arn]
}
