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
    aws_iam_policy.access_token_store_signing_key_kms_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn
  ]
  extra_tags = {
    Service = "auth-token"
  }
}

module "auth_token" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "auth-token"
  path_part       = "token"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                                = var.environment
    TXMA_AUDIT_QUEUE_URL                       = module.auth_ext_txma_audit.queue_url
    AUTHENTICATION_AUTHORIZATION_CALLBACK_URI  = var.authentication_auth_callback_uri
    ORCH_CLIENT_ID                             = var.orch_client_id
    AUTHENTICATION_BACKEND_URI                 = "https://${aws_api_gateway_rest_api.di_auth_ext_api.id}-${var.new_auth_api_vpc_endpoint_id != "" ? var.new_auth_api_vpc_endpoint_id : data.aws_vpc_endpoint.auth_api_vpc_endpoint.id}.execute-api.${var.aws_region}.amazonaws.com/${var.environment}/"
    ORCHESTRATION_BACKEND_URI                  = "https://${aws_api_gateway_rest_api.di_auth_ext_api.id}-${var.orch_api_vpc_endpoint_id}.execute-api.${var.aws_region}.amazonaws.com/${var.environment}/"
    ORCH_TO_AUTH_TOKEN_SIGNING_PUBLIC_KEY      = var.orch_to_auth_public_signing_key
    ORCH_STUB_TO_AUTH_TOKEN_SIGNING_PUBLIC_KEY = var.orch_stub_to_auth_public_signing_key
    INTERNAl_SECTOR_URI                        = var.internal_sector_uri
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

  snapstart = var.snapstart_enabled

  source_bucket           = aws_s3_bucket.auth_ext_source_bucket.bucket
  lambda_zip_file         = aws_s3_object.auth_ext_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.auth_ext_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.authentication_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.auth_token_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  dynatrace_secret      = local.dynatrace_secret
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  account_alias         = local.aws_account_alias

  depends_on = [
    aws_api_gateway_rest_api.di_auth_ext_api,
  ]
}
