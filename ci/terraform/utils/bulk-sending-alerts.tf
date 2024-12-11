resource "aws_cloudwatch_metric_alarm" "lambda_error_rate_cloudwatch_alarm" {
  count               = local.deploy_bulk_email_users_count
  alarm_name          = replace("${var.environment}-bulk-sending-error-rate-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = var.lambda_log_alarm_error_rate_threshold
  alarm_description   = "Lambda error rate of ${var.lambda_log_alarm_error_rate_threshold} has been reached in the ${aws_lambda_function.bulk_user_email_send_lambda[0].function_name} lambda.ACCOUNT: ${local.aws_account_alias}"

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
      period      = 900
      stat        = "Sum"
      unit        = "Count"

      dimensions = {
        FunctionName = aws_lambda_function.bulk_user_email_send_lambda[0].function_name
      }
    }
  }
  metric_query {
    id = "m2"
    metric {
      namespace   = "AWS/Lambda"
      metric_name = "Errors"
      period      = 900
      stat        = "Sum"
      unit        = "Count"

      dimensions = {
        FunctionName = aws_lambda_function.bulk_user_email_send_lambda[0].function_name
      }
    }
  }
  alarm_actions = [local.slack_event_sns_topic_arn]
}
