resource "aws_sqs_queue" "pending_email_check_queue" {
  name                      = "${var.environment}-pending-email-check-queue"
  delay_seconds             = 10
  max_message_size          = 2048
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.pending_email_check_dead_letter_queue.arn
    maxReceiveCount     = 1
  })

  tags = local.default_tags
}

resource "aws_sqs_queue" "pending_email_check_dead_letter_queue" {
  name = "${var.environment}-pending-email-check-dlq"

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  message_retention_seconds = 1209600

  tags = local.default_tags
}
