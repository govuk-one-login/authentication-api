module "email_notification_sqs_queue" {
  source = "../modules/sqs-queue"

  environment = var.environment
  queue_name = "email-notification"
  principals_arns = [module.userexists.lambda_iam_role_arn]
}