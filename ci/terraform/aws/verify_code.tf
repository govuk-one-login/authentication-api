module "verify_code" {
  source = "../modules/endpoint-module"

  endpoint_name   = "verify-code"
  endpoint_method = "POST"
  environment     = var.environment

  handler_environment_variables = {
    BASE_URL = var.api_base_url
    REDIS_HOST     = var.use_localstack ? var.external_redis_host : aws_elasticache_replication_group.sessions_store[0].primary_endpoint_address
    REDIS_PORT     = var.use_localstack ? var.external_redis_port : aws_elasticache_replication_group.sessions_store[0].port
    REDIS_PASSWORD = var.use_localstack ? var.external_redis_password : random_password.redis_password.result
    REDIS_TLS      = var.redis_use_tls
  }
  handler_function_name = "uk.gov.di.lambdas.VerifyCodeHandler::handleRequest"

  rest_api_id               = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id          = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn             = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
  security_group_id         = aws_vpc.authentication.default_security_group_id
  subnet_id                 = aws_subnet.authentication.*.id
  lambda_role_arn           = aws_iam_role.lambda_iam_role.arn
}