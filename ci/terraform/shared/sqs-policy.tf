data "aws_iam_policy_document" "pending_email_check_queue_subscription_policy_document" {
  statement {
    effect = "Allow"

    sid = "AllowReadDeleteAccessToPendingEmailCheckQueue"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.auth_check_account_id}:root"]
    }
    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
    ]
    resources = [
      aws_sqs_queue.pending_email_check_queue.arn,
    ]
  }

  dynamic "statement" {
    for_each = var.environment != "production" ? ["1"] : []
    content {
      sid    = "AllowSenderWriteAccessToPendingEmailCheckQueue"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = ["arn:aws:iam::${var.auth_new_account_id}:root"]
      }
      actions = [
        "sqs:SendMessage"
      ]
      resources = [
        aws_sqs_queue.pending_email_check_queue.arn,
      ]
    }
  }
}

resource "aws_sqs_queue_policy" "pending_email_check_queue_subscription" {
  queue_url = aws_sqs_queue.pending_email_check_queue.id

  policy = data.aws_iam_policy_document.pending_email_check_queue_subscription_policy_document.json
}
