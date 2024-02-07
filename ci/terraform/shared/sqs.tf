resource "aws_sqs_queue" "pending_email_check_queue" {
  name                      = "${var.environment}-pending-email-check-queue"
  delay_seconds             = 10
  max_message_size          = 2048
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10

  kms_master_key_id                 = var.use_localstack ? null : aws_kms_key.pending_email_check_queue_encryption_key.arn
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.pending_email_check_dead_letter_queue.arn
    maxReceiveCount     = 1
  })

  tags = local.default_tags
}

resource "aws_sqs_queue" "pending_email_check_dead_letter_queue" {
  name = "${var.environment}-pending-email-check-dlq"

  kms_master_key_id                 = var.use_localstack ? null : aws_kms_key.pending_email_check_queue_encryption_key.arn
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  message_retention_seconds = 1209600

  tags = local.default_tags
}

data "aws_iam_policy_document" "pending_email_queue_access_policy_document" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-pending-email-check-queue-access-policy"

  statement {
    effect    = "Allow"
    sid       = "AllowWriteAccessToPendingEmailCheckQueue"
    actions   = ["sqs:SendMessage", ]
    resources = [aws_sqs_queue.pending_email_check_queue.arn]
  }

  statement {
    effect = "Allow"
    sid    = "AllowAccessToKeyForEncryptingPayloads"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      aws_kms_key.pending_email_check_queue_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "pending_email_check_queue_access_policy" {
  name_prefix = "pending-email-queue-access-"
  path        = "/${var.environment}/"
  description = "IAM Policy for write access to the pending email queue"

  policy = data.aws_iam_policy_document.pending_email_queue_access_policy_document.json
}
