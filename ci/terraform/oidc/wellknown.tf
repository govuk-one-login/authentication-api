module "openid_configuration_role" {
  source = "../modules/lambda-role"

  role_name   = "openid-configuration"
  environment = var.environment
  vpc_arn     = local.authentication_vpc_arn
}

module "openid_configuration_discovery" {
  source = "../modules/endpoint-module"

  endpoint_name   = "openid-configuration"
  path_part       = "openid-configuration"
  endpoint_method = "GET"
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT         = var.environment
    BASE_URL            = local.api_base_url
    LOCALSTACK_ENDPOINT = var.use_localstack ? var.localstack_endpoint : null
  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.WellknownHandler::handleRequest"

  rest_api_id                            = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id                       = aws_api_gateway_resource.wellknown_resource.id
  execution_arn                          = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  lambda_zip_file                        = var.oidc_api_lambda_zip_file
  authentication_vpc_arn                 = local.authentication_vpc_arn
  security_group_ids                     = [local.authentication_security_group_id]
  subnet_id                              = local.authentication_subnet_ids
  lambda_role_arn                        = module.openid_configuration_role.arn
  logging_endpoint_enabled               = var.logging_endpoint_enabled
  logging_endpoint_arn                   = var.logging_endpoint_arn
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags

  keep_lambda_warm             = var.keep_lambdas_warm
  warmer_handler_function_name = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
  warmer_lambda_zip_file       = var.lambda_warmer_zip_file
  warmer_handler_environment_variables = {
    LAMBDA_MIN_CONCURRENCY = var.lambda_min_concurrency
  }

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
    module.openid_configuration_role
  ]
}
