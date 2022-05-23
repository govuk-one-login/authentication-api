resource "aws_sqs_queue" "spot_request_queue" {
  name                       = "${var.environment}-spot-request-queue"
  delay_seconds              = 10
  max_message_size           = 256000
  message_retention_seconds  = 1209600
  receive_wait_time_seconds  = 10
  visibility_timeout_seconds = 60

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.spot_request_dead_letter_queue.arn
    maxReceiveCount     = 3
  })

  kms_master_key_id                 = var.use_localstack ? null : aws_kms_key.spot_request_sqs_key.id
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  tags = local.default_tags
}

resource "aws_sqs_queue" "spot_request_dead_letter_queue" {
  name = "${var.environment}-spot-request-dlq"

  kms_master_key_id                 = var.use_localstack ? null : aws_kms_key.spot_request_sqs_key.id
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  message_retention_seconds = 3600 * 6

  tags = local.default_tags
}


data "aws_iam_policy_document" "spot_request_queue_policy_document" {
  statement {
    sid    = "SendSQS"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [module.ipv_callback_role.arn]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.spot_request_queue.arn
    ]
  }
  statement {
    sid    = "AllowSpotAccountToReceive"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${aws_ssm_parameter.spot_account_number.value}:root"]
    }

    actions = [
      "sqs:ReceiveMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.spot_request_queue.arn
    ]
  }
}

resource "aws_sqs_queue_policy" "spot_request_queue_policy" {
  depends_on = [
    data.aws_iam_policy_document.spot_request_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.spot_request_queue.id
  policy    = data.aws_iam_policy_document.spot_request_queue_policy_document.json
}

data "aws_iam_policy_document" "spot_request_dlq_queue_policy_document" {
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

    resources = [aws_sqs_queue.spot_request_dead_letter_queue.arn]
  }
}

resource "aws_sqs_queue_policy" "spot_request_dlq_queue_policy" {
  depends_on = [
    data.aws_iam_policy_document.spot_request_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.spot_request_dead_letter_queue.id
  policy    = data.aws_iam_policy_document.spot_request_dlq_queue_policy_document.json
}

data "aws_iam_policy_document" "spot_request_kms_key_policy" {
  policy_id = "key-policy-ssm"
  statement {
    sid = "Enable IAM User Permissions for root user"
    actions = [
      "kms:*",
    ]
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }
  statement {
    sid = "Give SPOT permissions to SQS KMS key"
    actions = [
      "kms:Decrypt",
    ]
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${aws_ssm_parameter.spot_account_number.value}:root"]
    }
    resources = ["*"]
  }
}

resource "aws_kms_key" "spot_request_sqs_key" {
  description             = "KMS key for SPOT request SQS queue encryption"
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.spot_request_kms_key_policy.json

  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"

  tags = local.default_tags
}

resource "aws_kms_alias" "spot_request_sqs_key_alias" {
  name          = "alias/${var.environment}-spot-request-sqs-queue-encryption-key"
  target_key_id = aws_kms_key.spot_request_sqs_key.id
}

data "aws_iam_policy_document" "spot_queue_encryption_policy" {
  version = "2012-10-17"

  statement {
    sid = "SpotQueueEncryption"

    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey"
    ]

    resources = [
      aws_kms_key.spot_request_sqs_key.arn
    ]
  }
}

resource "aws_iam_policy" "spot_queue_encryption_policy" {
  name_prefix = "spot-request-queue-kms-key-encryption-"
  path        = "/${var.environment}/spot/"
  description = "IAM policy for allowing encryption while writing to SPOT request queue"

  policy = data.aws_iam_policy_document.spot_queue_encryption_policy.json
}