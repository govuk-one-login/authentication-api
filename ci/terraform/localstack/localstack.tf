module "api_gateway_root" {
  source = "../modules/api-gateway-root"
  providers = {
    aws = aws.localstack
  }
  environment = var.environment
}

module "authorize" {
  source = "../modules/endpoint-module"
  providers = {
    aws = aws.localstack
  }

  endpoint_name   = "authorize"
  endpoint_method = "GET"
  handler_environment_variables = {
    BASE_URL = var.api_base_url
  }
  handler_function_name = "uk.gov.di.lambdas.AuthorisationHandler::handleRequest"

  rest_api_id               = module.api_gateway_root.di_authentication_api_id
  root_resource_id          = module.api_gateway_root.root_resource_id
  execution_arn             = module.api_gateway_root.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
}

module "openid_configuration_discovery" {
  source = "../modules/endpoint-module"
  providers = {
    aws = aws.localstack
  }

  endpoint_name   = "openid-configuration"
  endpoint_method = "GET"
  handler_environment_variables = {
    BASE_URL = var.api_base_url
  }
  handler_function_name = "uk.gov.di.lambdas.WellknownHandler::handleRequest"

  rest_api_id               = module.api_gateway_root.di_authentication_api_id
  root_resource_id          = module.api_gateway_root.wellknown_resource_id
  execution_arn             = module.api_gateway_root.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
}

module "jwks" {
  source = "../modules/endpoint-module"
  providers = {
    aws = aws.localstack
  }

  endpoint_name   = "jwk.json"
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
}

module "token" {
  source = "../modules/endpoint-module"
  providers = {
    aws = aws.localstack
  }

  endpoint_name   = "token"
  endpoint_method = "POST"
  handler_environment_variables = {
    BASE_URL = var.api_base_url
  }
  handler_function_name = "uk.gov.di.lambdas.TokenHandler::handleRequest"

  rest_api_id               = module.api_gateway_root.di_authentication_api_id
  root_resource_id          = module.api_gateway_root.root_resource_id
  execution_arn             = module.api_gateway_root.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
}

module "signup" {
  source = "../modules/endpoint-module"
  providers = {
    aws = aws.localstack
  }

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
}

module "userinfo" {
  source = "../modules/endpoint-module"
  providers = {
    aws = aws.localstack
  }

  endpoint_name   = "userinfo"
  endpoint_method = "GET"
  handler_environment_variables = {
    BASE_URL = var.api_base_url
  }
  handler_function_name = "uk.gov.di.lambdas.UserInfoHandler::handleRequest"

  rest_api_id               = module.api_gateway_root.di_authentication_api_id
  root_resource_id          = module.api_gateway_root.root_resource_id
  execution_arn             = module.api_gateway_root.execution_arn
  api_deployment_stage_name = var.api_deployment_stage_name
  lambda_zip_file           = var.lambda_zip_file
}
