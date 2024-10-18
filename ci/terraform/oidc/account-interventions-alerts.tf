data "aws_cloudwatch_log_group" "orchestration_redirect_lambda_log_group" {
  count = var.use_localstack ? 0 : 1
  name  = replace("/aws/lambda/${var.environment}-orchestration-redirect-lambda", ".", "")
}

resource "aws_cloudwatch_log_metric_filter" "account_interventions_metric_filter" {
  count          = var.use_localstack ? 0 : 1
  name           = replace("${var.environment}-account-interventions-p1-errors", ".", "")
  pattern        = "{($.${var.account_interventions_error_metric_name} = 1)}"
  log_group_name = data.aws_cloudwatch_log_group.orchestration_redirect_lambda_log_group[0].name

  metric_transformation {
    name      = replace("${var.environment}-account-interventions-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}

locals {
  isP1Alarm = var.environment == "production" && var.account_intervention_service_abort_on_error
}

resource "aws_cloudwatch_metric_alarm" "account_interventions_p1_cloudwatch_alarm" {
  count               = var.use_localstack ? 0 : 1
  alarm_name          = local.isP1Alarm ? replace("${var.environment}-P1-account-interventions-alarm", ".", "") : replace("${var.environment}-account-interventions-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.account_interventions_metric_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.account_interventions_metric_filter[0].metric_transformation[0].namespace
  period              = var.account_interventions_p1_alarm_error_time_period
  statistic           = "Sum"
  threshold           = var.account_interventions_p1_alarm_error_threshold
  alarm_description   = "${var.account_interventions_p1_alarm_error_threshold} or more Account Interventions errors have occurred in ${var.environment}.ACCOUNT: ${data.aws_iam_account_alias.current.account_alias}"
  alarm_actions       = [local.isP1Alarm ? data.aws_sns_topic.pagerduty_p1_alerts[0].arn : data.aws_sns_topic.slack_events.arn]
}
