resource "aws_cloudwatch_metric_alarm" "sqs_deadletter_cloudwatch_alarm" {
  count               = var.use_localstack ? 0 : 1
  alarm_name          = replace("${var.environment}-account-managament-dlq-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"

  dimensions = {
    QueueName = aws_sqs_queue.email_dead_letter_queue.name
  }
  alarm_description = "This metric monitors number of deadletters on the queue"
  alarm_actions     = [data.aws_sns_topic.slack_events.arn]
}

data "aws_sns_topic" "slack_events" {
  name = "${var.environment}-slack-events"
}