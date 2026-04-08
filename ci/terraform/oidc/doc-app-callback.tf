module "doc_app_callback_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "doc-app-callback-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    aws_iam_policy.doc_app_auth_kms_policy.arn,
    aws_iam_policy.doc_app_rp_client_id_parameter_policy.arn,
    module.oidc_txma_audit.access_policy_arn
  ]
  extra_tags = {
    Service = "doc-app-callback"
  }
}

module "doc-app-callback" {
  source          = "../modules/endpoint-module-v2"
  endpoint_name   = "doc-app-callback"
  path_part       = var.orch_doc_app_callback_enabled ? "doc-app-callback-auth" : "doc-app-callback"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    CUSTOM_DOC_APP_CLAIM_ENABLED       = var.custom_doc_app_claim_enabled
    DOC_APP_AUTHORISATION_CALLBACK_URI = var.doc_app_authorisation_callback_uri
    DOC_APP_AUTHORISATION_CLIENT_ID    = var.doc_app_authorisation_client_id
    DOC_APP_TOKEN_SIGNING_KEY_ALIAS    = local.doc_app_auth_key_alias_name
    DOC_APP_BACKEND_URI                = var.doc_app_backend_uri
    DOC_APP_CRI_DATA_ENDPOINT          = var.doc_app_cri_data_endpoint
    DOC_APP_JWKS_URL                   = var.doc_app_jwks_endpoint
    DOC_APP_CRI_DATA_V2_ENDPOINT       = var.doc_app_cri_data_v2_endpoint
    DOC_APP_AUD                        = var.doc_app_aud
    DOC_APP_NEW_AUD_CLAIM_ENABLED      = var.doc_app_new_aud_claim_enabled
    ENVIRONMENT                        = var.environment
    INTERNAl_SECTOR_URI                = var.internal_sector_uri
    AUTH_FRONTEND_BASE_URL             = "https://${local.frontend_fqdn}/"
    REDIS_KEY                          = local.redis_key
    TXMA_AUDIT_QUEUE_URL               = module.oidc_txma_audit.queue_url
    OIDC_API_BASE_URL                  = local.api_base_url
  }
  handler_function_name = "uk.gov.di.authentication.app.lambda.DocAppCallbackHandler::handleRequest"

  create_endpoint  = true
  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  memory_size      = lookup(var.performance_tuning, "doc-app-callback", local.default_performance_parameters).memory

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.doc_checking_app_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.doc_checking_app_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.authentication_oidc_redis_security_group_id,
    local.authentication_egress_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.doc_app_callback_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  api_key_required                       = false
  lambda_log_alarm_threshold             = 10

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
  ]
}
