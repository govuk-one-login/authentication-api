data "aws_cloudwatch_log_group" "ipv_callback_lambda_log_group" {
  name = replace("/aws/lambda/${var.environment}-ipv-callback-lambda", ".", "")

  depends_on = [
    module.ipv-callback
  ]
}


data "aws_cloudwatch_log_group" "spot_response_lambda_log_group" {
  name = replace("/aws/lambda/${var.environment}-spot-response-lambda", ".", "")
  depends_on = [
    module.ipv_spot_response_role_2
  ]
}


data "aws_cloudwatch_log_group" "processing_identity_lambda_log_group" {
  name = replace("/aws/lambda/${var.environment}-processing-identity-lambda", ".", "")

  depends_on = [
    module.processing-identity
  ]
}


resource "aws_cloudwatch_log_metric_filter" "ipv_callback_metric_filter" {
  name           = replace("${var.environment}-ipv-callback-p1-errors", ".", "")
  pattern        = "{($.level = \"ERROR\")}"
  log_group_name = data.aws_cloudwatch_log_group.ipv_callback_lambda_log_group.name

  metric_transformation {
    name      = replace("${var.environment}-ipv-handback-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}


resource "aws_cloudwatch_log_metric_filter" "spot_response_metric_filter" {
  name           = replace("${var.environment}-spot-response-p1-errors", ".", "")
  pattern        = "{($.level = \"ERROR\")}"
  log_group_name = data.aws_cloudwatch_log_group.spot_response_lambda_log_group.name

  metric_transformation {
    name      = replace("${var.environment}-ipv-handback-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}


resource "aws_cloudwatch_log_metric_filter" "processing_identity_metric_filter" {
  name           = replace("${var.environment}-processing-identity-p1-errors", ".", "")
  pattern        = "{($.level = \"ERROR\")}"
  log_group_name = data.aws_cloudwatch_log_group.processing_identity_lambda_log_group.name

  metric_transformation {
    name      = replace("${var.environment}-ipv-handback-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}


resource "aws_cloudwatch_metric_alarm" "ipv_handback_p1_cloudwatch_alarm" {
  alarm_name          = replace("${var.environment}-P1-ipv-handback-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.processing_identity_metric_filter.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.processing_identity_metric_filter.metric_transformation[0].namespace
  period              = var.ipv_p1_alarm_error_time_period
  statistic           = "Sum"
  threshold           = var.ipv_p1_alarm_error_threshold
  alarm_description   = "${var.ipv_p1_alarm_error_threshold} or more IPV handback errors have occurred in ${var.environment}.ACCOUNT: ${local.aws_account_alias}. Runbook: https://govukverify.atlassian.net/wiki/spaces/Orch/pages/5761204264/Runbook+IPV+handback+alarm"
  alarm_actions       = [var.environment == "production" ? data.aws_sns_topic.pagerduty_p1_alerts[0].arn : local.slack_event_sns_topic_arn]
  treat_missing_data  = "notBreaching"
}
