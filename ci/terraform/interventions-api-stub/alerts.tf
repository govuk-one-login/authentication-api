data "aws_sns_topic" "slack_events" {
  name = "${var.environment}-slack-events"
}
