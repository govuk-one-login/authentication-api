module "email_notification_sqs_queue" {
  source = "../modules/sqs-queue"
  providers = {
    aws = aws.localstack
  }
  environment = var.environment
  queue_name = "email-notification"
  principals_arns = [module.userexists.lambda_iam_role_arn]
}