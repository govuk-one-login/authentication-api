resource "aws_cloudwatch_metric_alarm" "sqs_deadletter_cloudwatch_alarm" {
  alarm_name          = replace("${var.environment}-email-notification-dlq-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = "300"
  statistic           = "Average"
  threshold           = var.notifications_dlq_alarm_threshold

  dimensions = {
    QueueName = aws_sqs_queue.email_dead_letter_queue.name
  }
  alarm_description = "${var.notifications_dlq_alarm_threshold} or more messages have appeared on the ${aws_sqs_queue.email_dead_letter_queue.name}. ACCOUNT: ${local.aws_account_alias}. Runbook: https://govukverify.atlassian.net/wiki/spaces/LO/pages/4164649233/BAU+Daytime+Support+Hygiene+and+Optimisation+Rota#SUP-7%3A-Resolve-DLQ-messages"
  alarm_actions     = [local.slack_event_sns_topic_arn]
}


resource "aws_cloudwatch_metric_alarm" "spot_request_sqs_dlq_cloudwatch_alarm" {
  alarm_name          = replace("${var.environment}-spot-request-queue-dlq-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = "60"
  statistic           = "Average"
  threshold           = var.dlq_alarm_threshold

  dimensions = {
    QueueName = aws_sqs_queue.spot_request_dead_letter_queue.name
  }
  alarm_description = "${var.dlq_alarm_threshold} or more messages have appeared on the ${aws_sqs_queue.spot_request_dead_letter_queue.name}. ACCOUNT: ${local.aws_account_alias}. Runbook: https://govukverify.atlassian.net/wiki/x/DYDMBgE"
  alarm_actions     = [local.slack_event_sns_topic_arn]
}


resource "aws_cloudwatch_metric_alarm" "spot_request_sqs_cloudwatch_alarm" {
  alarm_name          = replace("${var.environment}-spot-request-queue-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = "60"
  statistic           = "Maximum"
  threshold           = 10

  dimensions = {
    QueueName = aws_sqs_queue.spot_request_queue.name
  }
  alarm_description = "Age of the oldest message on ${aws_sqs_queue.spot_request_queue.name} exceeds 10 seconds. ACCOUNT: ${local.aws_account_alias}. Runbook: https://govukverify.atlassian.net/wiki/x/VIFoCAE"
  alarm_actions     = [local.slack_event_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "spot_request_sqs_cloudwatch_p1_alarm" {
  alarm_name          = replace("${var.environment}-P1-spot-request-queue-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = "60"
  statistic           = "Maximum"
  threshold           = 60

  dimensions = {
    QueueName = aws_sqs_queue.spot_request_queue.name
  }
  alarm_description = "Age of the oldest message on ${aws_sqs_queue.spot_request_queue.name} exceeds 60 seconds. ACCOUNT: ${local.aws_account_alias}. Runbook: https://govukverify.atlassian.net/wiki/x/VIFoCAE"
  alarm_actions     = [var.environment == "production" ? data.aws_sns_topic.pagerduty_p1_alerts[0].arn : local.slack_event_sns_topic_arn]
}


# Turning WAF blocked alerts off until we figure out how best to utilise them
#resource "aws_cloudwatch_metric_alarm" "waf_oidc_blocked_request_cloudwatch_alarm" {
#  alarm_name          = replace("${var.environment}-oidc-waf-blocked-requests-alarm", ".", "")
#  comparison_operator = "GreaterThanOrEqualToThreshold"
#  evaluation_periods  = "1"
#  metric_name         = "BlockedRequests"
#  namespace           = "AWS/WAFV2"
#  period              = "300"
#  statistic           = "Sum"
#  threshold           = var.waf_alarm_blocked_reqeuest_threshold
#
#  dimensions = {
#    Rule   = "ALL"
#    Region = var.aws_region
#    WebACL = aws_wafv2_web_acl.wafregional_web_acl_oidc_api[count.index].name
#  }
#
#  alarm_description = "${var.waf_alarm_blocked_reqeuest_threshold} or more blocked requests have been received by the ${aws_wafv2_web_acl.wafregional_web_acl_oidc_api[count.index].name} in the last 5 minutes"
#  alarm_actions     = [local.slack_event_sns_topic_arn]
#}

# Turning WAF blocked alerts off until we figure out how best to utilise them
#resource "aws_cloudwatch_metric_alarm" "waf_frontend_blocked_request_cloudwatch_alarm" {
#  alarm_name          = replace("${var.environment}-frontend-waf-blocked-requests-alarm", ".", "")
#  comparison_operator = "GreaterThanOrEqualToThreshold"
#  evaluation_periods  = "1"
#  metric_name         = "BlockedRequests"
#  namespace           = "AWS/WAFV2"
#  period              = "300"
#  statistic           = "Sum"
#  threshold           = var.waf_alarm_blocked_reqeuest_threshold
#
#  dimensions = {
#    Rule   = "ALL"
#    Region = var.aws_region
#    WebACL = aws_wafv2_web_acl.wafregional_web_acl_frontend_api[count.index].name
#  }
#
#  alarm_description = "${var.waf_alarm_blocked_reqeuest_threshold} or more blocked requests have been received by the ${aws_wafv2_web_acl.wafregional_web_acl_frontend_api[count.index].name} in the last 5 minutes"
#  alarm_actions     = [local.slack_event_sns_topic_arn]
#}
