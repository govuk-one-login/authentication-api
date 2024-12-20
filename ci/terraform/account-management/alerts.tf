resource "aws_cloudwatch_metric_alarm" "sqs_deadletter_cloudwatch_alarm" {
  alarm_name          = replace("${var.environment}-account-managament-dlq-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.dlq_alarm_threshold

  dimensions = {
    QueueName = aws_sqs_queue.email_dead_letter_queue.name
  }
  alarm_description = "${var.dlq_alarm_threshold} or more messages have appeared on the ${aws_sqs_queue.email_dead_letter_queue.name}"
  alarm_actions     = [local.slack_event_sns_topic_arn]
}
moved {
  from = aws_cloudwatch_metric_alarm.sqs_deadletter_cloudwatch_alarm[0]
  to   = aws_cloudwatch_metric_alarm.sqs_deadletter_cloudwatch_alarm
}

# Turning WAF blocked alerts off until we figure out how best to utilise them
#resource "aws_cloudwatch_metric_alarm" "waf_am_blocked_request_cloudwatch_alarm" {
#  alarm_name          = replace("${var.environment}-account-management-waf-blocked-requests-alarm", ".", "")
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
#    WebACL = aws_wafv2_web_acl.wafregional_web_acl_am_api[count.index].name
#  }
#
#  alarm_description = "${var.waf_alarm_blocked_reqeuest_threshold} or more blocked requests have been received by the ${aws_wafv2_web_acl.wafregional_web_acl_am_api[count.index].name} in the last 5 minutes"
#  alarm_actions     = [local.slack_event_sns_topic_arn]
#}
