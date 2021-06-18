module "send_notification" {
  source = "../modules/endpoint-module"

  endpoint_name   = "send-notification"
  endpoint_method = "POST"
  handler_environment_variables = {
    EMAIL_QUEUE_URL = module.email_notification_sqs_queue.queue_url
    REDIS_HOST     = aws_elasticache_replication_group.sessions_store.primary_endpoint_address
    REDIS_PORT     = aws_elasticache_replication_group.sessions_store.port
    REDIS_PASSWORD = random_password.redis_password.result
    REDIS_TLS      = "true"
  }
  handler_function_name = "uk.gov.di.lambdas.SendNotificationHandler::handleRequest"

  rest_api_id               = module.api_gateway_root.di_authentication_api_id
  root_resource_id          = module.api_gateway_root.root_resource_id
  execution_arn             = module.api_gateway_root.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
  security_group_id         = aws_vpc.authentication.default_security_group_id
  subnet_id                 = aws_subnet.authentication.*.id
}