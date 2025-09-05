resource "aws_cloudwatch_metric_alarm" "domestic_sms_quota_early_warning_alarm" {
  alarm_name          = "${var.environment}-domestic-sms-quota-early-warning-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "DomesticSmsQuotaEarlyWarning"
  namespace           = "Authentication"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Domestic SMS usage trending towards quota limit in ${var.environment}. ACCOUNT: ${local.aws_account_alias}"
  alarm_actions       = ["arn:aws:sns:eu-west-2:653994557586:authdev1-slack-events"]

  dimensions = {
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "international_sms_quota_early_warning_alarm" {
  alarm_name          = "${var.environment}-international-sms-quota-early-warning-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "InternationalSmsQuotaEarlyWarning"
  namespace           = "Authentication"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "International SMS usage trending towards quota limit in ${var.environment}. ACCOUNT: ${local.aws_account_alias}"
  alarm_actions       = ["arn:aws:sns:eu-west-2:653994557586:authdev1-slack-events"]

  dimensions = {
    Environment = var.environment
  }
}
