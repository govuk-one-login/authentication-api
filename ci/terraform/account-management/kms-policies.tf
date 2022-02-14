### ID token key permissions
data "aws_kms_key" "id_token_public_key" {
  key_id = "alias/${var.environment}-id-token-signing-key-alias"
}

data "aws_iam_policy_document" "kms_policy_document" {
  statement {
    sid    = "AllowAccessToKmsPublicKey"
    effect = "Allow"

    actions = [
      "kms:GetPublicKey",
    ]
    resources = [
      data.aws_kms_key.id_token_public_key.arn,
    ]
  }
}

resource "aws_iam_policy" "lambda_kms_policy" {
  name        = "${var.environment}--account-mgmt-lambda-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda"

  policy = data.aws_iam_policy_document.kms_policy_document.json
}

### Audit signing key permissions

data "aws_iam_policy_document" "account_management_audit_payload_kms_signing_policy_document" {
  statement {
    sid    = "AllowAccessToKmsAuditSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
      "kms:Verify"
    ]
    resources = [
      local.audit_signing_key_arn
    ]
  }

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
    sid    = "AllowLambdasToEncryptWithCustomKey"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      local.events_topic_encryption_key_arn
    ]
  }
}

resource "aws_iam_policy" "audit_signing_key_lambda_kms_signing_policy" {
  name        = "${var.environment}-account-management-lambda-audit-payload-kms-signing-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing of audit payloads"

  policy = data.aws_iam_policy_document.account_management_audit_payload_kms_signing_policy_document.json
}