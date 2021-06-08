module "jwks" {
  source = "../modules/endpoint-module"

  endpoint_name   = "jwks.json"
  endpoint_method = "GET"
  handler_environment_variables = {
    BASE_URL = var.api_base_url
  }
  handler_function_name = "uk.gov.di.lambdas.JwksHandler::handleRequest"

  rest_api_id               = module.api_gateway_root.di_authentication_api_id
  root_resource_id          = module.api_gateway_root.wellknown_resource_id
  execution_arn             = module.api_gateway_root.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
  security_group_id         = aws_security_group.elasticache_security_group.id
}