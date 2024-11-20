resource "aws_cloudwatch_log_metric_filter" "lambda_error_metric_filter" {
  count          = var.use_localstack ? 0 : 1
  name           = replace("${var.environment}-${var.endpoint_name}-errors", ".", "")
  pattern        = "{($.level = \"ERROR\")}"
  log_group_name = aws_cloudwatch_log_group.lambda_log_group[0].name

  metric_transformation {
    name      = replace("${var.environment}-${var.endpoint_name}-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}

locals {
  base_error_alarm_description      = "${var.lambda_log_alarm_threshold} or more errors have occurred in the ${var.environment} ${var.endpoint_name} lambda.ACCOUNT: ${data.aws_iam_account_alias.current.account_alias}"
  error_alarm_description           = var.runbook_link == "" ? local.base_error_alarm_description : "${local.base_error_alarm_description}. Runbook: ${var.runbook_link}"
  base_error_rate_alarm_description = "Lambda error rate of ${var.lambda_log_alarm_error_rate_threshold} has been reached in the ${var.environment} ${var.endpoint_name} lambda.ACCOUNT: ${data.aws_iam_account_alias.current.account_alias}"
  error_rate_alarm_description      = var.runbook_link == "" ? local.base_error_rate_alarm_description : "${local.base_error_rate_alarm_description}. Runbook: ${var.runbook_link}"
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
  alarm_description   = local.error_alarm_description
  alarm_actions       = [data.aws_sns_topic.slack_events.arn]
}

resource "aws_cloudwatch_metric_alarm" "lambda_error_rate_cloudwatch_alarm" {
  count               = var.use_localstack || var.lambda_error_rate_alarm_disabled ? 0 : 1
  alarm_name          = replace("${var.environment}-${var.endpoint_name}-error-rate-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = var.lambda_log_alarm_error_rate_threshold
  alarm_description   = local.error_rate_alarm_description

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
        FunctionName = aws_lambda_function.endpoint_lambda.function_name
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
        FunctionName = aws_lambda_function.endpoint_lambda.function_name
      }
    }
  }
  alarm_actions = [data.aws_sns_topic.slack_events.arn]
}

data "aws_sns_topic" "slack_events" {
  name = "${var.environment}-slack-events"
}
