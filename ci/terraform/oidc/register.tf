module "client_registry_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "client-registry-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_client_registry_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
  ]
}

module "register" {
  count  = var.client_registry_api_enabled ? 1 : 0
  source = "../modules/endpoint-module"

  endpoint_name   = "register"
  path_part       = "register"
  endpoint_method = "POST"

  handler_environment_variables = {
    ENVIRONMENT             = var.environment
    BASE_URL                = local.api_base_url
    DYNAMO_ENDPOINT         = var.use_localstack ? var.lambda_dynamo_endpoint : null
    EVENTS_SNS_TOPIC_ARN    = aws_sns_topic.events.arn
    AUDIT_SIGNING_KEY_ALIAS = local.audit_signing_key_alias_name
    LOCALSTACK_ENDPOINT     = var.use_localstack ? var.localstack_endpoint : null
  }
  handler_function_name = "uk.gov.di.authentication.clientregistry.lambda.ClientRegistrationHandler::handleRequest"

  create_endpoint        = false
  rest_api_id            = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id       = aws_api_gateway_resource.register_resource.id
  execution_arn          = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  authentication_vpc_arn = local.authentication_vpc_arn

  source_bucket                  = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file                = aws_s3_bucket_object.client_api_release_zip.key
  lambda_zip_file_version        = aws_s3_bucket_object.client_api_release_zip.version_id
  warmer_lambda_zip_file         = aws_s3_bucket_object.warmer_release_zip.key
  warmer_lambda_zip_file_version = aws_s3_bucket_object.warmer_release_zip.version_id

  security_group_ids                     = [local.authentication_security_group_id]
  subnet_id                              = local.authentication_subnet_ids
  lambda_role_arn                        = module.client_registry_role.arn
  environment                            = var.environment
  logging_endpoint_enabled               = var.logging_endpoint_enabled
  logging_endpoint_arn                   = var.logging_endpoint_arn
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
    aws_api_gateway_resource.register_resource,
  ]
}
