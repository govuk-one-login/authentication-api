resource "aws_sqs_queue" "back_channel_logout_queue" {
  name                      = "${var.environment}-back-channel-logout-queue"
  max_message_size          = 2048
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.back_channel_logout_dead_letter_queue.arn
    maxReceiveCount     = 3
  })

  kms_master_key_id                 = var.cmk_for_back_channel_logout_enabled ? aws_kms_key.back_channel_logout_queue_encryption_key.arn : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_sqs_queue" "back_channel_logout_dead_letter_queue" {
  name = "${var.environment}-back-channel-logout-dlq"

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  message_retention_seconds = 3600 * 6
}

data "aws_iam_policy_document" "back_channel_logout_dlq_queue_policy_document" {
  statement {
    sid    = "SendAndReceive"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ReceiveMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [aws_sqs_queue.back_channel_logout_dead_letter_queue.arn]
  }
}

resource "aws_sqs_queue_policy" "back_channel_logout_dlq_queue_policy" {
  queue_url = aws_sqs_queue.back_channel_logout_dead_letter_queue.id
  policy    = data.aws_iam_policy_document.back_channel_logout_dlq_queue_policy_document.json
}

resource "aws_kms_key" "back_channel_logout_queue_encryption_key" {
  description              = "KMS encryption key for back channel logout queue"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true

  policy = data.aws_iam_policy_document.back_channel_logout_queue_encryption_key_access_policy.json
}

resource "aws_kms_alias" "back_channel_logout_queue_encryption_key_alias" {
  name          = "alias/${var.environment}-back-channel-logout-queue-kms-alias"
  target_key_id = aws_kms_key.back_channel_logout_queue_encryption_key.id
}

data "aws_iam_policy_document" "back_channel_logout_queue_encryption_key_access_policy" {
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

data "aws_iam_policy_document" "back_channel_logout_queue_write_access_policy_document" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-back-channel-logout-queue-write-access-policy"

  statement {
    effect = "Allow"
    sid    = "AllowWriteAccessToBackChannelLogoutQueue"
    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes"
    ]
    resources = [aws_sqs_queue.back_channel_logout_queue.arn]
  }

  statement {
    effect = "Allow"
    sid    = "AllowAccessToKeyForEncryptingPayloads"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      aws_kms_key.back_channel_logout_queue_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "back_channel_logout_queue_write_access_policy" {
  name_prefix = "back-channel-logout-queue-write-access-"
  path        = "/${var.environment}/"
  description = "IAM Policy for write access to the back channel logout queue"

  policy = data.aws_iam_policy_document.back_channel_logout_queue_write_access_policy_document.json
}

data "aws_iam_policy_document" "back_channel_logout_queue_read_access_policy_document" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-back-channel-logout-queue-read-access-policy"

  statement {
    effect = "Allow"
    sid    = "AllowReadAccessToBackChannelLogoutQueue"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ChangeMessageVisibility"
    ]
    resources = [aws_sqs_queue.back_channel_logout_queue.arn]
  }

  statement {
    effect = "Allow"
    sid    = "AllowAccessToKeyForDecryptingPayloads"
    actions = [
      "kms:Decrypt"
    ]
    resources = [
      aws_kms_key.back_channel_logout_queue_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "back_channel_logout_queue_read_access_policy" {
  name_prefix = "back-channel-logout-queue-read-access-"
  path        = "/${var.environment}/"
  description = "IAM Policy for read access to the back channel logout queue"

  policy = data.aws_iam_policy_document.back_channel_logout_queue_read_access_policy_document.json
}
