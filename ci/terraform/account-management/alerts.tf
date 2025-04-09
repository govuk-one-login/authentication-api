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
