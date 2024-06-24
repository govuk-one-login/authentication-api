resource "aws_kms_key" "storage_token_signing_key_ecc" {
  description              = "KMS signing key (ECC) for VC storage token"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  policy = data.aws_iam_policy_document.storage_token_signing_key_access_policy.json

  tags = local.default_tags
}

resource "aws_kms_alias" "storage_token_signing_key_alias" {
  name          = "alias/${var.environment}-storage-token-signing-key-ecc-alias"
  target_key_id = aws_kms_key.storage_token_signing_key_ecc.key_id
}

data "aws_iam_policy_document" "storage_token_signing_key_access_policy" {
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
    sid    = "AllowOrchAccessToKmsStorageTokenSigningKey-${var.environment}"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.orch_account_id}:root"]
    }
  }
}

resource "aws_kms_key" "mfa_reset_signing_key_ecc" {
  description              = "KMS signing key (ECC) for MFA reset token"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  policy = data.aws_iam_policy_document.mfa_reset_signing_key_access_policy.json

  tags = local.default_tags
}

resource "aws_kms_alias" "mfa_reset_signing_key_alias" {
  name          = "alias/${var.environment}-mfa-reset-signing-key-ecc-alias"
  target_key_id = aws_kms_key.mfa_reset_signing_key_ecc.key_id
}

data "aws_iam_policy_document" "mfa_reset_signing_key_access_policy" {
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


resource "aws_kms_key" "mfa_reset_jar_signing_key_ecc" {
  description              = "KMS signing key (ECC) for JARs sent from Authentication to IPV for MFA reset"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  policy = data.aws_iam_policy_document.mfa_reset_jar_signing_key_access_policy.json

  tags = local.default_tags
}

resource "aws_kms_alias" "mfa_reset_jar_signing_key_alias" {
  name          = "alias/${var.environment}-mfa-reset-jar-signing-key-ecc-alias"
  target_key_id = aws_kms_key.mfa_reset_jar_signing_key_ecc.key_id
}

data "aws_iam_policy_document" "mfa_reset_jar_signing_key_access_policy" {
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
