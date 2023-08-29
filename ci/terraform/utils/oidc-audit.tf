data "aws_sqs_queue" "oidc_txma_audit_queue" {

  name = "${var.environment}-oidc-txma-audit-queue"
}

data "aws_kms_alias" "oidc_txma_audit_queue_encryption_key_alias" {
  name = "alias/${var.environment}-oidc-audit-kms-alias"
}

data "aws_iam_policy_document" "txma_audit_queue_access_policy_document" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-txma-audit-queue-access-policy"

  statement {
    effect    = "Allow"
    sid       = "AllowWriteAccessToTxmaAuditQueue"
    actions   = ["sqs:SendMessage", ]
    resources = [data.aws_sqs_queue.oidc_txma_audit_queue.arn]
  }

  statement {
    effect = "Allow"
    sid    = "AllowAccessToKeyForEncryptingPayloads"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      data.aws_kms_alias.oidc_txma_audit_queue_encryption_key_alias.target_key_arn
    ]
  }
}

resource "aws_iam_policy" "txma_audit_queue_access_policy" {
  name_prefix = "txma-audit-queue-access-"
  path        = "/${var.environment}/"
  description = "IAM Policy for write access to the TxMA audit queue"

  policy = data.aws_iam_policy_document.txma_audit_queue_access_policy_document.json
}
