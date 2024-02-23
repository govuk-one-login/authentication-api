data "aws_cloudwatch_log_group" "ipv_authorize_lambda_log_group" {
  name = replace("/aws/lambda/${var.environment}-ipv-authorize-lambda", ".", "")

  depends_on = [
    module.ipv-authorize
  ]
}
moved {
  from = data.aws_cloudwatch_log_group.ipv_authorize_lambda_log_group[0]
  to   = data.aws_cloudwatch_log_group.ipv_authorize_lambda_log_group
}

resource "aws_cloudwatch_log_metric_filter" "ipv_authorize_metric_filter" {
  name           = replace("${var.environment}-ipv-handoff-p1-errors", ".", "")
  pattern        = "{($.level = \"ERROR\")}"
  log_group_name = data.aws_cloudwatch_log_group.ipv_authorize_lambda_log_group.name

  metric_transformation {
    name      = replace("${var.environment}-ipv-handoff-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}
moved {
  from = aws_cloudwatch_log_metric_filter.ipv_authorize_metric_filter[0]
  to   = aws_cloudwatch_log_metric_filter.ipv_authorize_metric_filter
}

data "aws_cloudwatch_log_group" "authentication_callback_lambda_log_group" {
  name = replace("/aws/lambda/${var.environment}-orchestration-redirect-lambda", ".", "")

  depends_on = [
    module.authentication_callback
  ]
}
moved {
  from = data.aws_cloudwatch_log_group.authentication_callback_lambda_log_group[0]
  to   = data.aws_cloudwatch_log_group.authentication_callback_lambda_log_group
}

resource "aws_cloudwatch_log_metric_filter" "authentication_callback_metric_filter" {
  name           = replace("${var.environment}-ipv-handoff-p1-post-split-errors", ".", "")
  pattern        = "{($.level = \"ERROR\")}"
  log_group_name = data.aws_cloudwatch_log_group.authentication_callback_lambda_log_group.name

  metric_transformation {
    name      = replace("${var.environment}-ipv-handoff-post-split-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}
moved {
  from = aws_cloudwatch_log_metric_filter.authentication_callback_metric_filter[0]
  to   = aws_cloudwatch_log_metric_filter.authentication_callback_metric_filter
}

resource "aws_cloudwatch_metric_alarm" "ipv_handoff_p1_cloudwatch_alarm" {
  alarm_name          = replace("${var.environment}-P1-ipv-handoff-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = var.ipv_p1_alarm_error_threshold
  alarm_description   = "${var.ipv_p1_alarm_error_threshold} or more IPV handoff errors have occurred in ${var.environment}.ACCOUNT: ${data.aws_iam_account_alias.current.account_alias}"
  alarm_actions       = [var.environment == "production" ? data.aws_sns_topic.pagerduty_p1_alerts[0].arn : data.aws_sns_topic.slack_events.arn]

  metric_query {
    id          = "combined_error_count"
    label       = "ipv-handoff-pre-and-post-split-combined-error-count"
    expression  = "ipv_authorize_lambda_error_count+authentication_callback_lambda_error_count"
    return_data = true
  }

  metric_query {
    id = "ipv_authorize_lambda_error_count"

    metric {
      metric_name = aws_cloudwatch_log_metric_filter.ipv_authorize_metric_filter.metric_transformation[0].name
      namespace   = aws_cloudwatch_log_metric_filter.ipv_authorize_metric_filter.metric_transformation[0].namespace
      period      = var.ipv_p1_alarm_error_time_period
      stat        = "Sum"
    }
  }

  metric_query {
    id = "authentication_callback_lambda_error_count"

    metric {
      metric_name = aws_cloudwatch_log_metric_filter.authentication_callback_metric_filter.metric_transformation[0].name
      namespace   = aws_cloudwatch_log_metric_filter.authentication_callback_metric_filter.metric_transformation[0].namespace
      period      = var.ipv_p1_alarm_error_time_period
      stat        = "Sum"
    }
  }
}
moved {
  from = aws_cloudwatch_metric_alarm.ipv_handoff_p1_cloudwatch_alarm[0]
  to   = aws_cloudwatch_metric_alarm.ipv_handoff_p1_cloudwatch_alarm
}
