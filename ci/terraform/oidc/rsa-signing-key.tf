resource "aws_kms_key" "id_token_signing_key_rsa" {
  description              = "KMS signing key (RSA) for ID tokens"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_4096"

  policy = data.aws_iam_policy_document.id_token_signing_key_rsa_access_policy.json

  tags = local.default_tags
}

resource "aws_kms_alias" "id_token_signing_key_alias" {
  name          = "alias/${var.environment}-id-token-signing-key-rsa-alias"
  target_key_id = aws_kms_key.id_token_signing_key_rsa.key_id
}

data "aws_iam_policy_document" "id_token_signing_key_rsa_access_policy" {
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

  statement {
    sid    = "AllowOrchAccessToKmsIdTokenRsaSigningKey-${var.environment}"
    effect = "Allow"

    actions = [
      "kms:GetPublicKey",
      "kms:Sign"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.orch_account_id}:root"]
    }
  }
}
