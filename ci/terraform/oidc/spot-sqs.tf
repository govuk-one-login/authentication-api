resource "aws_sqs_queue" "spot_request_queue" {
  count                     = var.ipv_api_enabled ? 1 : 0
  name                      = "${var.environment}-spot-request-queue"
  delay_seconds             = 10
  max_message_size          = 2048
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.spot_request_dead_letter_queue[0].arn
    maxReceiveCount     = 3
  })

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  tags = local.default_tags
}

resource "aws_sqs_queue" "spot_request_dead_letter_queue" {
  count = var.ipv_api_enabled ? 1 : 0
  name  = "${var.environment}-spot-request-dlq"

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  message_retention_seconds = 3600 * 6

  tags = local.default_tags
}


data "aws_iam_policy_document" "spot_request_queue_policy_document" {
  count = var.ipv_api_enabled ? 1 : 0
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
      aws_sqs_queue.spot_request_queue[0].arn
    ]
  }
}

resource "aws_sqs_queue_policy" "spot_request_queue_policy" {
  count = var.ipv_api_enabled ? 1 : 0
  depends_on = [
    data.aws_iam_policy_document.spot_request_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.spot_request_queue[0].id
  policy    = data.aws_iam_policy_document.spot_request_queue_policy_document[0].json
}

data "aws_iam_policy_document" "spot_request_dlq_queue_policy_document" {
  count = var.ipv_api_enabled ? 1 : 0
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

    resources = [aws_sqs_queue.spot_request_dead_letter_queue[0].arn]
  }
}

resource "aws_sqs_queue_policy" "spot_request_dlq_queue_policy" {
  count = var.ipv_api_enabled ? 1 : 0
  depends_on = [
    data.aws_iam_policy_document.spot_request_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.spot_request_dead_letter_queue[0].id
  policy    = data.aws_iam_policy_document.spot_request_dlq_queue_policy_document[0].json
}