resource "aws_sqs_queue" "txma_audit_queue" {
  name                      = "${var.environment}-${var.service_name}-txma-audit-queue"
  message_retention_seconds = 1209600

  kms_master_key_id                 = aws_kms_key.txma_audit_queue_encryption_key.arn
  kms_data_key_reuse_period_seconds = 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.txma_audit_dead_letter_queue.arn
    maxReceiveCount     = 3
  })

  tags = var.default_tags
}

resource "aws_sqs_queue" "txma_audit_dead_letter_queue" {
  name = "${var.environment}-${var.service_name}-txma-audit-dlq"

  kms_master_key_id                 = aws_kms_key.txma_audit_queue_encryption_key.arn
  kms_data_key_reuse_period_seconds = 300

  message_retention_seconds = 604800

  tags = var.default_tags
}

resource "aws_sqs_queue_policy" "txma_audit_queue_subscription" {
  queue_url = aws_sqs_queue.txma_audit_queue.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"

      Principal = {
        AWS = ["arn:aws:iam::${var.txma_account_id}:root"]
      }

      Action = [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
      ]

      Resource = [
        aws_sqs_queue.txma_audit_queue.arn,
      ]
    }]
  })
}

