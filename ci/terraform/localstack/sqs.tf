module "email_notification_sqs_queue" {
  source = "../modules/sqs-queue"
  providers = {
    aws = aws.localstack
  }

  account_id = "123456789012"
  environment = var.environment
  queue_name = "email-notification"
}