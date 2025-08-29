resource "aws_sns_topic_subscription" "pagerduty_auth_alerts_topic_subscription" {
  count     = contains(["production", "integration"], var.environment) ? 1 : 0
  topic_arn = aws_sns_topic.auth_pagerduty_alerts.arn
  protocol  = "https"
  endpoint  = var.pagerduty_alerts_endpoint
}
