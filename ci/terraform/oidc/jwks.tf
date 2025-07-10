module "oidc_jwks_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-jwks-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.oidc_default_id_token_public_key_kms_policy.arn,
    aws_iam_policy.doc_app_auth_kms_policy.arn,
    local.doc_app_credential_encryption_policy_arn
  ]
  extra_tags = {
    Service = "jwks.json"
  }
}

module "jwks" {
  source = "../modules/endpoint-module-v2"

  endpoint_name           = "jwks.json"
  endpoint_name_sanitized = "jwksjson"

  path_part       = var.orch_jwks_enabled ? "jwks-auth.json" : "jwks.json"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                          = var.environment
    DOC_APP_TOKEN_SIGNING_KEY_ALIAS      = local.doc_app_auth_key_alias_name
    EXTERNAL_TOKEN_SIGNING_KEY_ALIAS     = local.id_token_signing_key_alias_name
    EXTERNAL_TOKEN_SIGNING_KEY_RSA_ALIAS = aws_kms_alias.id_token_signing_key_alias.name
    HEADERS_CASE_INSENSITIVE             = "false"
  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.JwksHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_resource.wellknown_resource.id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  memory_size      = lookup(var.performance_tuning, "jwks", local.default_performance_parameters).memory

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.oidc_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.oidc_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids                     = [local.authentication_security_group_id]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.oidc_jwks_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  snapstart = var.snapstart_enabled

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
  ]
}
