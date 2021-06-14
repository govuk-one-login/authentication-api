module "authorize" {
  source = "../modules/endpoint-module"

  endpoint_name   = "authorize"
  endpoint_method = "GET"
  handler_environment_variables = {
    BASE_URL       = var.api_base_url
    LOGIN_URI      = "https://di-authentication-frontend.london.cloudapps.digital/"
    REDIS_URL      = "rediss://${aws_elasticache_replication_group.sessions_store.primary_endpoint_address}:${aws_elasticache_replication_group.sessions_store.port}"
    REDIS_PASSWORD = random_password.redis_password.result
  }
  handler_function_name = "uk.gov.di.lambdas.AuthorisationHandler::handleRequest"

  rest_api_id               = module.api_gateway_root.di_authentication_api_id
  root_resource_id          = module.api_gateway_root.root_resource_id
  execution_arn             = module.api_gateway_root.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
  security_group_id         = aws_vpc.authentication.default_security_group_id
  subnet_id                 = aws_subnet.authentication.*.id
}