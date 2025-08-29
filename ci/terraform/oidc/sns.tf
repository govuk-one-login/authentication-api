resource "aws_sns_topic" "auth_pagerduty_alerts" {
  name = "${var.environment}-auth-pagerduty-alerts"
}

data "aws_iam_policy_document" "auth_pagerduty_alerts_policy_document" {
  statement {
    sid    = "AllowCloudWatchAlarmsToPublish"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.auth_pagerduty_alerts.arn]
  }

  statement {
    sid    = "AllowAccountOwnerFullAccess"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = [
      "SNS:Subscribe",
      "SNS:GetTopicAttributes",
      "SNS:SetTopicAttributes"
    ]
    resources = [aws_sns_topic.auth_pagerduty_alerts.arn]
  }
}

resource "aws_sns_topic_policy" "auth_pagerduty_alerts_policy" {
  arn    = aws_sns_topic.auth_pagerduty_alerts.arn
  policy = data.aws_iam_policy_document.auth_pagerduty_alerts_policy_document.json
}
