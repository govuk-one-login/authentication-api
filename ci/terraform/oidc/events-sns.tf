resource "aws_sns_topic" "events" {
  name              = "${var.environment}-events"
  kms_master_key_id = "alias/aws/sns"
  tags              = local.default_tags
}

data "aws_iam_policy_document" "events_policy_document" {
  version   = "2008-10-17"
  policy_id = "${var.environment}-events-sns-topic-policy"

  statement {
    effect = "Allow"
    sid    = "${var.environment}-events-sns-topic-policy-publish"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "SNS:Publish",
      "SNS:RemovePermission",
      "SNS:SetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:Receive",
      "SNS:AddPermission",
      "SNS:Subscribe"
    ]
    resources = [aws_sns_topic.events.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    effect = "Allow"
    sid    = "${var.environment}-events-sns-topic-policy-subscribe"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "SNS:Subscribe",
      "SNS:Receive"
    ]
    resources = [aws_sns_topic.events.arn]
  }
}

resource "aws_sns_topic_policy" "events" {
  policy = data.aws_iam_policy_document.events_policy_document.json
  arn    = aws_sns_topic.events.arn
}