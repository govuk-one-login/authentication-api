resource "aws_sqs_queue" "queue" {
  name                      = "${var.environment}-${var.queue_name}-queue"
  delay_seconds             = 10
  max_message_size          = 2048
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10
}

data "aws_iam_policy_document" "queue_policy_document" {
  statement {
    sid    = "SendSQS"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = var.sender_principal_arns
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.queue.arn
    ]
  }

  statement {
    sid    = "ReceiveSQS"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [aws_iam_role.lambda_iam_role.arn]
    }

    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.queue.arn
    ]
  }
}

resource "aws_sqs_queue_policy" "queue_policy" {
  queue_url = aws_sqs_queue.queue.id
  policy    = data.aws_iam_policy_document.queue_policy_document.json
}

resource "aws_lambda_event_source_mapping" "lambda_sqs_mapping" {
  event_source_arn = aws_sqs_queue.queue.arn
  function_name    = aws_lambda_function.sqs_lambda.arn

  depends_on = [
    aws_sqs_queue.queue,
    aws_sqs_queue_policy.queue_policy,
    aws_lambda_function.sqs_lambda,
    aws_iam_role.lambda_iam_role,
  ]
}
