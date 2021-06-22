module "email_notification_sqs_queue" {
  source = "../modules/sqs-queue"
  providers = {
    aws = aws.localstack
  }
  environment = var.environment
  name = "email-notification"
  sender_principal_arns = [module.userexists.lambda_iam_role_arn]
  handler_environment_variables = {
    VERIFY_EMAIL_TEMPLATE_ID = "b7dbb02f-941b-4d72-ad64-84cbe5d77c2e"
    NOTIFY_API_KEY = "a988d9fca677c75b3677e878b259bedf03846afa23d8f5ad1e3b1d55a53558bbab0fca6affc841546846ca2be0afeb91ee24b8b4dc9e9a2e3f1dd56c043d8068"
  }
  handler_function_name = "uk.gov.di.lambdas.NotificationHandler::handleRequest"
  lambda_zip_file = var.lambda_zip_file
  security_group_id         = aws_vpc.authentication.default_security_group_id
  subnet_id                 = aws_subnet.authentication.*.id
}
