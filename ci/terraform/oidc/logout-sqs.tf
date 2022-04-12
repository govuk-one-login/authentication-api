resource "aws_sqs_queue" "back_channel_logout_queue" {
  name                      = "${var.environment}-back-channel-logout-queue"
  delay_seconds             = 10
  max_message_size          = 2048
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.back_channel_logout_dead_letter_queue.arn
    maxReceiveCount     = 3
  })

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  tags = local.default_tags
}

resource "aws_sqs_queue" "back_channel_logout_dead_letter_queue" {
  name = "${var.environment}-back-channel-logout-dlq"

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  message_retention_seconds = 3600 * 6

  tags = local.default_tags
}

data "aws_iam_policy_document" "back_channel_logout_queue_policy_document" {
  statement {
    sid    = "SendSQS"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [module.oidc_logout_role.arn]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.back_channel_logout_queue.arn
    ]
  }

  statement {
    sid    = "ReceiveSQS"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [module.backchannel_logout_request_role.arn]
    }

    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.back_channel_logout_queue.arn
    ]
  }
}

resource "aws_sqs_queue_policy" "back_channel_logout_queue_policy" {
  depends_on = [
    data.aws_iam_policy_document.back_channel_logout_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.back_channel_logout_queue.id
  policy    = data.aws_iam_policy_document.back_channel_logout_queue_policy_document.json
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
  depends_on = [
    data.aws_iam_policy_document.back_channel_logout_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.back_channel_logout_dead_letter_queue.id
  policy    = data.aws_iam_policy_document.back_channel_logout_dlq_queue_policy_document.json
}