data "aws_sns_topic" "pagerduty_p1_alerts" {
  name = "${var.environment}-pagerduty-p1-alerts"
}

data "aws_sns_topic" "slack_events" {
  name = "${var.environment}-slack-events"
}