### Audit signing key access

data "aws_iam_policy_document" "audit_payload_kms_signing_policy_document" {
  statement {
    sid       = "AllowAccessToKmsAuditSigningKey"
    effect    = "Allow"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:Verify"]
    resources = [local.audit_signing_key_arn]
  }
}

resource "aws_iam_policy" "audit_signing_key_lambda_kms_signing_policy" {
  name_prefix = "audit-payload-kms-signing-policy"
  path        = "/${var.environment}/auth-ext-default/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing of audit payloads"

  policy = data.aws_iam_policy_document.audit_payload_kms_signing_policy_document.json
}

data "aws_iam_policy_document" "auth_code_dynamo_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToAuthCodeTableKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:Decrypt*",
    ]
    resources = [
      local.auth_code_store_signing_configuration_arn
    ]
  }
}

resource "aws_iam_policy" "auth_code_dynamo_encryption_key_kms_policy" {
  name_prefix = "auth-code-table-encryption-key-kms-policy"
  path        = "/${var.environment}/auth-ext-default/"
  description = "IAM policy for managing KMS encryption of the auth code table"

  policy = data.aws_iam_policy_document.auth_code_dynamo_encryption_key_policy_document.json
}

data "aws_iam_policy_document" "access_token_store_signing_key_kms_policy_document" {
  statement {
    sid    = "AllowAccessToAccessTokenStoreKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Decrypt*",
    ]
    resources = [
      local.access_token_store_signing_key_arn
    ]
  }
}

resource "aws_iam_policy" "access_token_store_signing_key_kms_policy" {
  name_prefix = "access-token-store-signing-key-kms-policy"
  path        = "/${var.environment}/auth-ext-default/"
  description = "IAM policy for managing Access Token store KMS key access"

  policy = data.aws_iam_policy_document.access_token_store_signing_key_kms_policy_document.json
}