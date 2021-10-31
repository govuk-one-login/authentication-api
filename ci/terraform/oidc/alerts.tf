resource "aws_cloudwatch_metric_alarm" "sqs_deadletter_cloudwatch_alarm" {
  count               = var.use_localstack ? 0 : 1
  alarm_name          = replace("${var.environment}-email-notification-dlq-alarm", ".", "")
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
  alarm_actions     = [data.aws_sns_topic.slack_events.arn]
}

data "aws_sns_topic" "slack_events" {
  name = "${var.environment}-slack-events"
}