resource "aws_kms_key" "storage_token_signing_key_ecc" {
  description              = "KMS signing key (ECC) for VC storage token"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  policy = data.aws_iam_policy_document.storage_token_signing_key_access_policy.json
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

resource "aws_kms_key" "mfa_reset_token_signing_key_ecc" {
  description              = "KMS signing key (ECC) for signing the storage token claim in MFA reset JARs sent to IPV from Auth"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  policy = data.aws_iam_policy_document.mfa_reset_signing_key_access_policy.json
}

resource "aws_kms_alias" "mfa_reset_token_signing_key_alias" {
  name          = "alias/${var.environment}-mfa-reset-token-signing-key-ecc-alias"
  target_key_id = aws_kms_key.mfa_reset_token_signing_key_ecc.key_id
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

  dynamic "statement" {
    for_each = var.auth_new_account_id == "" ? [] : [1]

    content {
      sid    = "AllowCrossAccountAccess"
      effect = "Allow"

      actions = [
        "kms:GetPublicKey",
        "kms:Sign"
      ]
      principals {
        type        = "AWS"
        identifiers = ["arn:aws:iam::${var.auth_new_account_id}:root"]
      }
      resources = ["*"]
    }
  }
}

## ipv_reverification_request_signing_key - V1 ##
# NOTE: Before deleting these V1 resources, ensure they are no longer being used on higher environments such as production.

resource "aws_kms_key" "ipv_reverification_request_signing_key" {
  description              = "KMS signing key (ECC) for JARs sent from Authentication to IPV for MFA reset"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  policy = data.aws_iam_policy_document.ipv_reverification_request_signing_key_access_policy.json
}

resource "aws_kms_alias" "ipv_reverification_request_signing_key_v1_alias" {
  name          = "alias/${var.environment}-ipv_reverification_request_signing_key_v1"
  target_key_id = aws_kms_key.ipv_reverification_request_signing_key.key_id
}

## / ipv_reverification_request_signing_key - V1 ##

## ipv_reverification_request_signing_key - V2 ##

resource "aws_kms_key" "ipv_reverification_request_signing_key_v2" {
  description              = "KMS signing key (ECC) for JARs sent from Authentication to IPV for MFA reset (v2)"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  policy = data.aws_iam_policy_document.ipv_reverification_request_signing_key_access_policy.json
}

resource "aws_kms_alias" "ipv_reverification_request_signing_key_v2_alias" {
  name          = "alias/${var.environment}-ipv_reverification_request_signing_key_v2"
  target_key_id = aws_kms_key.ipv_reverification_request_signing_key_v2.key_id
}

## / ipv_reverification_request_signing_key - V2 ##

resource "aws_kms_alias" "ipv_reverification_request_signing_key_alias" {
  name          = "alias/${var.environment}-ipv_reverification_request_signing_key"
  target_key_id = var.environment != "production" ? aws_kms_key.ipv_reverification_request_signing_key_v2.key_id : aws_kms_key.ipv_reverification_request_signing_key.key_id
}

data "aws_iam_policy_document" "ipv_reverification_request_signing_key_access_policy" {
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

  dynamic "statement" {
    for_each = var.auth_new_account_id == "" ? [] : [1]

    content {
      sid    = "AllowCrossAccountAccess"
      effect = "Allow"

      actions = [
        "kms:GetPublicKey",
        "kms:Sign"
      ]
      principals {
        type        = "AWS"
        identifiers = ["arn:aws:iam::${var.auth_new_account_id}:root"]
      }
      resources = ["*"]
    }
  }
}
