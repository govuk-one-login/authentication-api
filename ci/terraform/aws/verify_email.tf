module "verify_email" {
  source = "../modules/endpoint-module"

  endpoint_name   = "verify-email"
  endpoint_method = "POST"
  handler_environment_variables = {
    EMAIL_QUEUE_URL = module.email_notification_sqs_queue.queue_url
  }
  handler_function_name = "uk.gov.di.lambdas.SendUserEmailHandler::handleRequest"

  rest_api_id               = module.api_gateway_root.di_authentication_api_id
  root_resource_id          = module.api_gateway_root.root_resource_id
  execution_arn             = module.api_gateway_root.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
  security_group_id         = aws_vpc.authentication.default_security_group_id
  subnet_id                 = aws_subnet.authentication.*.id
}