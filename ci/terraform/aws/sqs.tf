module "email_notification_sqs_queue" {
  source = "../modules/sqs-queue"

  environment = var.environment
  name = "email-notification"
  sender_principal_arns = [module.verify_email.lambda_iam_role_arn]

  handler_environment_variables = {
    VERIFY_EMAIL_TEMPLATE_ID = "b7dbb02f-941b-4d72-ad64-84cbe5d77c2e"
    NOTIFY_API_KEY = var.notify_api_key
  }
  handler_function_name = "uk.gov.di.lambdas.NotificationHandler::handleRequest"

  lambda_zip_file           = var.lambda_zip_file
  security_group_id         = aws_vpc.authentication.default_security_group_id
  subnet_id                 = aws_subnet.authentication.*.id
}