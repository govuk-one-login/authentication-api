resource "aws_sqs_queue" "pending_email_check_queue" {
  name                       = "${var.environment}-pending-email-check-queue"
  delay_seconds              = 10
  max_message_size           = 2048
  message_retention_seconds  = 1209600
  receive_wait_time_seconds  = 10
  visibility_timeout_seconds = 270

  kms_master_key_id                 = aws_kms_key.pending_email_check_queue_encryption_key.arn
  kms_data_key_reuse_period_seconds = 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.pending_email_check_dead_letter_queue.arn
    maxReceiveCount     = 1
  })
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

resource "aws_sqs_queue" "pending_email_check_dead_letter_queue" {
  name = "${var.environment}-pending-email-check-dlq"

  kms_master_key_id                 = aws_kms_key.pending_email_check_queue_encryption_key.arn
  kms_data_key_reuse_period_seconds = 300

  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_metric_alarm" "pending_email_check_dlq_cloudwatch_alarm" {
  alarm_name          = replace("${var.environment}-pending-email-check-dlq-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.dlq_alarm_threshold

  dimensions = {
    QueueName = aws_sqs_queue.pending_email_check_dead_letter_queue.name
  }
  alarm_description = "${var.dlq_alarm_threshold} or more messages have appeared on the ${aws_sqs_queue.pending_email_check_dead_letter_queue.name}. Runbook: https://govukverify.atlassian.net/wiki/spaces/LO/pages/4164649233/BAU+Daytime+Support+Hygiene+and+Optimisation+Rota#SUP-7%3A-Resolve-DLQ-messages"
  alarm_actions     = [aws_sns_topic.slack_events.arn]
}
