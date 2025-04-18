module "mfa_reset_storage_token_jwk_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "mfa-reset-jwk-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.mfa_reset_storage_token_kms_signing_policy.arn
  ]
  extra_tags = {
    Service = "mfa-reset-jwk.json"
  }
}

module "mfa_reset_storage_token_jwk" {
  source = "../modules/endpoint-module-v2"

  endpoint_name           = "mfa-reset-jwk.json"
  endpoint_name_sanitized = "mfa-reset-jwkjson"

  path_part       = "mfa-reset-jwk.json"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                               = var.environment
    DOC_APP_TOKEN_SIGNING_KEY_ALIAS           = local.doc_app_auth_key_alias_name
    MFA_RESET_STORAGE_TOKEN_SIGNING_KEY_ALIAS = aws_kms_alias.mfa_reset_token_signing_key_alias.arn
  }
  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.MfaResetStorageTokenJwkHandler::handleRequest"
  runbook_link          = "https://govukverify.atlassian.net/l/cp/LfLKwP4s"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_resource.auth_frontend_wellknown_resource.id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "mfa-reset-jwk", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "mfa-reset-jwk", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "mfa-reset-jwk", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "mfa-reset-jwk", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.frontend_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.frontend_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids                     = [local.authentication_security_group_id]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.mfa_reset_storage_token_jwk_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_frontend_api,
    aws_api_gateway_resource.auth_frontend_wellknown_resource,
  ]
}
