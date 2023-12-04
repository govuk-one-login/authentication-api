module "auth_token_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "auth-ext-token-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    module.auth_ext_txma_audit.access_policy_arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.audit_events_sns_policy.arn,
    aws_iam_policy.dynamo_auth_code_store_read_access_policy.arn,
    aws_iam_policy.dynamo_auth_code_store_write_access_policy.arn,
    aws_iam_policy.dynamo_access_token_store_read_access_policy.arn,
    aws_iam_policy.dynamo_access_token_store_write_access_policy.arn,
    aws_iam_policy.auth_code_dynamo_encryption_key_kms_policy.arn,
    aws_iam_policy.access_token_store_signing_key_kms_policy.arn
  ]
}

module "auth_token" {
  source = "../modules/endpoint-module"

  endpoint_name   = "auth-token"
  path_part       = "token"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                               = var.environment
    TXMA_AUDIT_QUEUE_URL                      = module.auth_ext_txma_audit.queue_url
    LOCALSTACK_ENDPOINT                       = null
    DYNAMO_ENDPOINT                           = null
    AUTHENTICATION_AUTHORIZATION_CALLBACK_URI = var.authentication_auth_callback_uri
    ORCH_CLIENT_ID                            = var.orch_client_id
    AUTHENTICATION_BACKEND_URI                = "https://${aws_api_gateway_rest_api.di_auth_ext_api.id}-${data.aws_vpc_endpoint.auth_api_vpc_endpoint.id}.execute-api.${var.aws_region}.amazonaws.com/${var.environment}/"
    ORCH_TO_AUTH_TOKEN_SIGNING_PUBLIC_KEY     = var.orch_to_auth_public_signing_key
    SUPPORT_AUTH_ORCH_SPLIT                   = var.support_auth_orch_split
  }
  handler_function_name = "uk.gov.di.authentication.external.lambda.TokenHandler::handleRequest"
  handler_runtime       = "java17"

  rest_api_id      = aws_api_gateway_rest_api.di_auth_ext_api.id
  root_resource_id = aws_api_gateway_rest_api.di_auth_ext_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_auth_ext_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "auth-token", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "auth-token", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "auth-token", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "auth-token", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.auth_ext_source_bucket.bucket
  lambda_zip_file         = aws_s3_object.auth_ext_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.auth_ext_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_security_group_id,
  ]
  subnet_id                              = local.authentication_subnet_ids
  lambda_role_arn                        = module.auth_token_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags

  use_localstack = false

  depends_on = [
    aws_api_gateway_rest_api.di_auth_ext_api,
  ]
}
