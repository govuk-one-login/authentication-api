module "identity" {
  count  = var.ipv_api_enabled ? 1 : 0
  source = "../modules/endpoint-module"

  endpoint_name   = "identity"
  path_part       = "identity"
  endpoint_method = "GET"
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT             = var.environment
    EVENTS_SNS_TOPIC_ARN    = aws_sns_topic.events.arn
    AUDIT_SIGNING_KEY_ALIAS = local.audit_signing_key_alias_name
    LOCALSTACK_ENDPOINT     = var.use_localstack ? var.localstack_endpoint : null
    DYNAMO_ENDPOINT         = var.use_localstack ? var.lambda_dynamo_endpoint : null
  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.IdentityHandler::handleRequest"

  rest_api_id            = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id       = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn          = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  lambda_zip_file        = var.oidc_api_lambda_zip_file
  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = local.authentication_subnet_ids
  lambda_role_arn                        = module.oidc_default_role.arn
  logging_endpoint_enabled               = var.logging_endpoint_enabled
  logging_endpoint_arn                   = var.logging_endpoint_arn
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags

  keep_lambda_warm             = var.keep_lambdas_warm
  warmer_handler_function_name = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
  warmer_lambda_zip_file       = var.lambda_warmer_zip_file
  warmer_security_group_ids    = [local.authentication_security_group_id]
  warmer_handler_environment_variables = {
    LAMBDA_MIN_CONCURRENCY = var.lambda_min_concurrency
  }

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
  ]
}
