resource "aws_sqs_queue" "pending_email_check_queue" {
  name                      = "${var.environment}-pending-email-check-queue"
  delay_seconds             = 10
  max_message_size          = 2048
  message_retention_seconds = 1209600
  receive_wait_time_seconds = 10

  kms_master_key_id                 = var.use_localstack ? null : "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = var.use_localstack ? null : 300

  tags = local.default_tags
}
