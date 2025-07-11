module "oidc_authorize_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-authorize-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.doc_app_auth_kms_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.ipv_capacity_parameter_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    aws_iam_policy.orch_to_auth_kms_policy.arn,
    aws_iam_policy.auth_public_encryption_key_parameter_policy.arn,
    local.client_registry_encryption_policy_arn,
    local.doc_app_credential_encryption_policy_arn,
    local.user_credentials_encryption_policy_arn,
    aws_iam_policy.oidc_token_kms_signing_policy.arn
  ]
  extra_tags = {
    Service = "authorize"
  }
}

module "authorize" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "authorize"
  path_part       = var.orch_authorisation_enabled ? "authorize-auth" : "authorize"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    DOMAIN_NAME                          = local.service_domain
    TXMA_AUDIT_QUEUE_URL                 = module.oidc_txma_audit.queue_url
    ENVIRONMENT                          = var.environment
    HEADERS_CASE_INSENSITIVE             = "false"
    IDENTITY_ENABLED                     = var.ipv_api_enabled
    AUTH_FRONTEND_BASE_URL               = "https://${local.frontend_fqdn}/"
    OIDC_API_BASE_URL                    = local.api_base_url
    ORCH_CLIENT_ID                       = var.orch_client_id
    REDIS_KEY                            = local.redis_key
    TERMS_CONDITIONS_VERSION             = var.terms_and_conditions
    INTERNAl_SECTOR_URI                  = var.internal_sector_uri
    ORCH_TO_AUTH_TOKEN_SIGNING_KEY_ALIAS = local.orch_to_auth_signing_key_alias_name
    DOC_APP_AUTHORISATION_URI            = var.doc_app_authorisation_uri
    DOC_APP_AUTHORISATION_CALLBACK_URI   = var.doc_app_authorisation_callback_uri
    DOC_APP_AUTHORISATION_CLIENT_ID      = var.doc_app_authorisation_client_id
    DOC_APP_JWKS_URL                     = var.doc_app_jwks_endpoint
    DOC_APP_TOKEN_SIGNING_KEY_ALIAS      = local.doc_app_auth_key_alias_name
    DOC_APP_DOMAIN                       = var.doc_app_domain
    DOC_APP_AUD                          = var.doc_app_aud
    DOC_APP_NEW_AUD_CLAIM_ENABLED        = var.doc_app_new_aud_claim_enabled
    CUSTOM_DOC_APP_CLAIM_ENABLED         = var.custom_doc_app_claim_enabled
    ORCH_REDIRECT_URI                    = var.orch_redirect_uri
    EXTERNAL_TOKEN_SIGNING_KEY_ALIAS     = local.id_token_signing_key_alias_name
    USE_STRONGLY_CONSISTENT_READS        = var.use_strongly_consistent_reads
  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.AuthorisationHandler::handleRequest"
  rest_api_id           = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id      = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn         = aws_api_gateway_rest_api.di_authentication_api.execution_arn

  lambda_error_rate_alarm_disabled = true
  memory_size                      = lookup(var.performance_tuning, "authorize", local.default_performance_parameters).memory

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.oidc_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.oidc_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = var.authorize_protected_subnet_enabled ? [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
    local.authentication_egress_security_group_id,
    ] : [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = var.authorize_protected_subnet_enabled ? local.authentication_protected_subnet_ids : local.authentication_private_subnet_ids
  lambda_role_arn                        = module.oidc_authorize_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  snapstart = false # uses redis

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
  ]
}
