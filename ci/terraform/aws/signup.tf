module "signup" {
  source = "../modules/endpoint-module"

  endpoint_name   = "signup"
  endpoint_method = "POST"
  handler_environment_variables = {
    BASE_URL = var.api_base_url
  }
  handler_function_name = "uk.gov.di.lambdas.SignUpHandler::handleRequest"

  rest_api_id               = module.api_gateway_root.di_authentication_api_id
  root_resource_id          = module.api_gateway_root.root_resource_id
  execution_arn             = module.api_gateway_root.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
  security_group_id         = aws_security_group.elasticache_security_group.id
  subnet_id                 = aws_subnet.authentication.*.id

}