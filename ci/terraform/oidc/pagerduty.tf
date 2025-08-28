resource "aws_sns_topic_subscription" "pagerduty_auth_alerts_topic_subscription" {
  count     = var.environment == "production" ? 1 : 0
  topic_arn = aws_sns_topic.auth_pagerduty_alerts.arn
  protocol  = "https"
  endpoint  = var.pagerduty_p1_alerts_endpoint
}
