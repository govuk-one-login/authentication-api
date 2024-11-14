resource "aws_kms_key" "txma_audit_queue_encryption_key" {
  description              = "KMS signing key for encrypting ${var.service_name} TxMA audit queue at rest"
  deletion_window_in_days  = 30
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  enable_key_rotation      = true

  policy = data.aws_iam_policy_document.txma_audit_queue_encryption_key_access_policy.json

  tags = var.extra_tags
}

resource "aws_kms_alias" "txma_audit_queue_encryption_key_alias" {
  name          = "alias/${var.environment}-${var.service_name}-audit-kms-alias"
  target_key_id = aws_kms_key.txma_audit_queue_encryption_key.key_id
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "txma_audit_queue_encryption_key_access_policy" {
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
    sid    = "AllowTxmaAccessToKmsAuditEncryptionKey-${var.environment}"
    effect = "Allow"

    actions = [
      "kms:Decrypt"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.txma_account_id}:root"]
    }
  }
}
