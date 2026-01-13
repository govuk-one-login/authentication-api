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

  dynamic "statement" {
    for_each = local.is_acceptance_test_env ? [1] : []
    content {
      sid    = "AllowAccessToTestIDTokenKey"
      effect = "Allow"

      actions = [
        "kms:GetPublicKey",
        "kms:Sign",
        "kms:Verify",
      ]
      resources = [
        aws_kms_key.test_id_token_signing_key[0].arn,
      ]
    }
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

# Test ID Token Signing KMS key (for acceptance tests)
resource "aws_kms_key" "test_id_token_signing_key" {
  count = local.is_acceptance_test_env ? 1 : 0

  description              = "KMS signing key for ID tokens used for acceptance tests"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
}

resource "aws_kms_alias" "test_id_token_signing_key_alias" {
  count = local.is_acceptance_test_env ? 1 : 0

  name          = "alias/${var.environment}-test-id-token-signing-key-alias"
  target_key_id = aws_kms_key.test_id_token_signing_key[0].key_id
}

data "aws_iam_policy_document" "test_id_token_signing_key_access_policy" {
  count = local.is_acceptance_test_env ? 1 : 0

  statement {
    sid    = "DefaultAccessPolicy"
    effect = "Allow"

    actions = [
      "kms:*"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key_policy" "test_id_token_signing_key_policy" {
  count = local.is_acceptance_test_env ? 1 : 0

  key_id = aws_kms_key.test_id_token_signing_key[0].id
  policy = data.aws_iam_policy_document.test_id_token_signing_key_access_policy[0].json
}
