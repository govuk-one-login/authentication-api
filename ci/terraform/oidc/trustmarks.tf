module "oidc_trustmarks_role" {
  source = "../modules/lambda-role"

  role_name   = "oidc-trustmarks-role"
  environment = var.environment
  vpc_arn     = local.authentication_vpc_arn
}

module "trustmarks" {
  source = "../modules/endpoint-module"

  endpoint_name   = "trustmark"
  path_part       = "trustmark"
  endpoint_method = "GET"
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT              = var.environment
    OIDC_API_BASE_URL        = local.api_base_url
    EVENTS_SNS_TOPIC_ARN     = aws_sns_topic.events.arn
    AUDIT_SIGNING_KEY_ALIAS  = local.audit_signing_key_alias_name
    LOCALSTACK_ENDPOINT      = var.use_localstack ? var.localstack_endpoint : null
    DYNAMO_ENDPOINT          = var.use_localstack ? var.lambda_dynamo_endpoint : null
    HEADERS_CASE_INSENSITIVE = var.use_localstack ? "true" : "false"
  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.TrustMarkHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "trustmark", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "trustmark", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "trustmark", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "trustmark", local.default_performance_parameters).scaling_trigger

  source_bucket                  = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file                = aws_s3_bucket_object.oidc_api_release_zip.key
  lambda_zip_file_version        = aws_s3_bucket_object.oidc_api_release_zip.version_id
  warmer_lambda_zip_file         = aws_s3_bucket_object.warmer_release_zip.key
  warmer_lambda_zip_file_version = aws_s3_bucket_object.warmer_release_zip.version_id
  code_signing_config_arn        = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn                 = local.authentication_vpc_arn
  security_group_ids                     = [local.authentication_security_group_id]
  subnet_id                              = local.authentication_subnet_ids
  lambda_role_arn                        = module.oidc_trustmarks_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags

  keep_lambda_warm             = var.keep_lambdas_warm
  warmer_handler_function_name = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
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
