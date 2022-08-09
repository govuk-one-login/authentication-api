data "aws_iam_policy_document" "txma_audit_queue_access_policy_document" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-txma-audit-queue-access-policy"

  statement {
    effect    = "Allow"
    sid       = "AllowWriteAccessToTxmaAuditQueue"
    actions   = ["sqs:SendMessage", ]
    resources = [aws_sqs_queue.txma_audit_queue.arn]
  }

  statement {
    effect = "Allow"
    sid    = "AllowAccessToKeyForEncryptingPayloads"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      aws_kms_key.txma_audit_queue_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "txma_audit_queue_access_policy" {
  name_prefix = "txma-audit-queue-access-"
  path        = "/${var.environment}/"
  description = "IAM Policy for write access to the TxMA audit queue"

  policy = data.aws_iam_policy_document.txma_audit_queue_access_policy_document.json
}