module "oidc_userinfo_role_2" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-userinfo-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.oidc_token_kms_signing_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    local.client_registry_encryption_policy_arn,
    local.doc_app_credential_encryption_policy_arn,
    local.user_credentials_encryption_policy_arn
  ]
  extra_tags = {
    Service = "userinfo"
  }
}

module "userinfo" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "userinfo"
  path_part       = var.orch_userinfo_enabled ? "userinfo-auth" : "userinfo"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                          = var.environment
    TXMA_AUDIT_QUEUE_URL                 = module.oidc_txma_audit.queue_url
    REDIS_KEY                            = local.redis_key
    EXTERNAL_TOKEN_SIGNING_KEY_ALIAS     = local.id_token_signing_key_alias_name
    EXTERNAL_TOKEN_SIGNING_KEY_RSA_ALIAS = aws_kms_alias.id_token_signing_key_alias.name
    IDENTITY_ENABLED                     = var.ipv_api_enabled
    INTERNAl_SECTOR_URI                  = var.internal_sector_uri
    OIDC_API_BASE_URL                    = local.api_base_url
    USE_STRONGLY_CONSISTENT_READS        = var.use_strongly_consistent_reads
  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.UserInfoHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  memory_size      = lookup(var.performance_tuning, "userinfo", local.default_performance_parameters).memory

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.oidc_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.oidc_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.oidc_userinfo_role_1.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
  ]
}
