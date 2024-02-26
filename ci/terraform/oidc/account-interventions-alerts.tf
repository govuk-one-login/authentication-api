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

resource "aws_cloudwatch_metric_alarm" "account_interventions_p1_cloudwatch_alarm" {
  count               = var.use_localstack ? 0 : 1
  alarm_name          = replace("${var.environment}-P1-account-interventions-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.account_interventions_metric_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.account_interventions_metric_filter[0].metric_transformation[0].namespace
  period              = var.account_interventions_p1_alarm_error_time_period
  statistic           = "Sum"
  threshold           = var.account_interventions_p1_alarm_error_threshold
  alarm_description   = "${var.account_interventions_p1_alarm_error_threshold} or more Account Interventions errors have occurred in ${var.environment}.ACCOUNT: ${data.aws_iam_account_alias.current.account_alias}"
  alarm_actions       = [var.environment == "production" && var.account_intervention_service_abort_on_error ? data.aws_sns_topic.pagerduty_p1_alerts[0].arn : data.aws_sns_topic.slack_events.arn]
}

data "aws_cloudwatch_log_group" "auth_account_interventions_lambda_log_group" {
  count = var.environment == "production" || var.environment == "integration" ? 0 : 1
  name  = replace("/aws/lambda/${var.environment}-account-interventions-lambda", ".", "")
}

resource "aws_cloudwatch_log_metric_filter" "auth_account_interventions_metric_filter" {
  count          = var.environment == "production" || var.environment == "integration" ? 0 : 1
  name           = replace("${var.environment}-auth-account-interventions-errors-responses", ".", "")
  pattern        = "{($.${var.account_interventions_error_metric_name} = 1)}"
  log_group_name = data.aws_cloudwatch_log_group.auth_account_interventions_lambda_log_group[0].name

  metric_transformation {
    name      = replace("${var.environment}-auth-account-interventions-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "auth_account_interventions_cloudwatch_alarm" {
  count               = var.environment == "production" || var.environment == "integration" ? 0 : 1
  alarm_name          = replace("${var.environment}-auth-account-interventions-cloudwatch-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.auth_account_interventions_metric_filter[0].metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.auth_account_interventions_metric_filter[0].metric_transformation[0].namespace
  period              = var.account_interventions_p1_alarm_error_time_period
  statistic           = "Sum"
  threshold           = var.account_interventions_p1_alarm_error_threshold
  alarm_description   = "${var.account_interventions_p1_alarm_error_threshold} or more Account Interventions errors have occurred in ${var.environment}.ACCOUNT: ${data.aws_iam_account_alias.current.account_alias}"
  alarm_actions       = var.environment == "production" ? [data.aws_sns_topic.slack_events.arn] : []
}

resource "aws_cloudwatch_metric_alarm" "account_interventions_error_rate_p1_cloudwatch_alarm" {
  count               = var.environment == "production" || var.environment == "integration" ? 0 : 1
  alarm_name          = replace("${var.environment}-P1-auth-account-interventions-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = var.account_interventions_p1_alarm_error_threshold
  alarm_description   = "Lambda error rate of ${var.account_interventions_p1_alarm_error_threshold} has been reached in the ${var.environment}-account-interventions-lambda lambda. ACCOUNT: ${data.aws_iam_account_alias.current.account_alias}"

  metric_query {
    id          = "e1"
    return_data = true
    expression  = "m2/m1*100"
    label       = "Error Rate"
  }

  metric_query {
    id = "m1"
    metric {
      namespace   = "AWS/Lambda"
      metric_name = "Invocations"
      period      = 60
      stat        = "Sum"
      unit        = "Count"

      dimensions = {
        FunctionName = replace("${var.environment}-account-interventions-lambda", ".", "")
      }
    }
  }
  metric_query {
    id = "m2"
    metric {
      namespace   = "AWS/Lambda"
      metric_name = "Errors"
      period      = 60
      stat        = "Sum"
      unit        = "Count"

      dimensions = {
        FunctionName = replace("${var.environment}-account-interventions-lambda", ".", "")
      }
    }
  }
  alarm_actions = [var.environment == "production" && var.account_intervention_service_abort_on_error ? data.aws_sns_topic.pagerduty_p1_alerts[0].arn : data.aws_sns_topic.slack_events.arn]
}
