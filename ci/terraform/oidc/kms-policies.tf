### ID Token signing key access

data "aws_iam_policy_document" "kms_policy_document" {
  statement {
    sid       = "AllowAccessToKmsSigningKey"
    effect    = "Allow"
    actions   = ["kms:GetPublicKey"]
    resources = [local.id_token_signing_key_arn]
  }
}

resource "aws_iam_policy" "oidc_default_id_token_public_key_kms_policy" {
  name_prefix = "id-token-kms-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing ID token public signing key access"

  policy = data.aws_iam_policy_document.kms_policy_document.json
}

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
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing of audit payloads"

  policy = data.aws_iam_policy_document.audit_payload_kms_signing_policy_document.json
}

### IPV Token signing key access

data "aws_iam_policy_document" "ipv_token_auth_kms_policy_document" {
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = [
      local.ipv_token_auth_signing_key_arn
    ]
  }
}

resource "aws_iam_policy" "ipv_token_auth_kms_policy" {
  name_prefix = "kms-ipv-token-auth-policy"
  path        = "/${var.environment}/ipv-token/"
  description = "IAM policy for managing IPV authentication token KMS key access"

  policy = data.aws_iam_policy_document.ipv_token_auth_kms_policy_document.json
}