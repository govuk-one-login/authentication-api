data "aws_sns_topic" "events" {
  name = "${var.environment}-events"
}

data "aws_iam_policy_document" "audit_events_policy_document" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-events-sns-topic-policy"

  statement {
    effect = "Allow"
    sid    = "GiveEventsSnsTopicPolicyPublish"
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
    resources = [data.aws_sns_topic.events.arn]
  }

  statement {
    effect = "Allow"
    sid    = "AllowLambdasToEncryptWithCustomKey" # pragma: allowlist secret
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      local.events_topic_encryption_key_arn
    ]
  }
}

resource "aws_iam_policy" "audit_events_sns_policy" {
  name        = "${var.environment}-auth-ext-lambda-sns-policy"
  path        = "/${var.environment}/auth-ext-default/"
  description = "IAM policy for managing KMS connection for a lambda"

  policy = data.aws_iam_policy_document.audit_events_policy_document.json
}
