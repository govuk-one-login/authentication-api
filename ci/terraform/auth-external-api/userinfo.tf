module "auth_userinfo_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "auth-ext-userinfo-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    module.auth_ext_txma_audit.access_policy_arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.audit_events_sns_policy.arn,
    aws_iam_policy.dynamo_access_token_store_read_access_policy.arn,
    aws_iam_policy.dynamo_access_token_store_write_access_policy.arn,
    aws_iam_policy.access_token_store_signing_key_kms_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    local.user_credentials_encryption_policy_arn,
    aws_iam_policy.dynamo_auth_session_write_policy.arn,
    aws_iam_policy.dynamo_auth_session_read_policy.arn
  ]
  extra_tags = {
    Service = "auth-userinfo"
  }
}

module "auth_userinfo" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "auth-userinfo"
  path_part       = "userinfo"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT          = var.environment
    TXMA_AUDIT_QUEUE_URL = module.auth_ext_txma_audit.queue_url
    REDIS_KEY            = local.redis_key
    INTERNAl_SECTOR_URI  = var.internal_sector_uri
  }
  handler_function_name = "uk.gov.di.authentication.external.lambda.UserInfoHandler::handleRequest"
  handler_runtime       = "java17"

  rest_api_id      = aws_api_gateway_rest_api.di_auth_ext_api.id
  root_resource_id = aws_api_gateway_rest_api.di_auth_ext_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_auth_ext_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "auth-userinfo", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "auth-userinfo", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "auth-userinfo", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "auth-userinfo", local.default_performance_parameters).scaling_trigger

  snapstart = var.snapstart_enabled

  source_bucket           = aws_s3_bucket.auth_ext_source_bucket.bucket
  lambda_zip_file         = aws_s3_object.auth_ext_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.auth_ext_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.auth_userinfo_role.arn
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
