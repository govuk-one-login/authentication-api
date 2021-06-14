resource "aws_sqs_queue" "queue" {
  name                      = "${var.environment}-${var.queue_name}-queue"
  delay_seconds             = 10
  max_message_size          = 2048
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10
}

data "aws_iam_policy_document" "queue_policy_document" {
  statement {
    sid    = "SendAndReceive"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ReceiveMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [aws_sqs_queue.queue.arn]
  }
}

resource "aws_sqs_queue_policy" "event" {
  queue_url = aws_sqs_queue.queue.id
  policy    = data.aws_iam_policy_document.queue_policy_document.json
}
