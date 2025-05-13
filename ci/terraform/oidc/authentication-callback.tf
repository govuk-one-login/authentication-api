module "oidc_api_authentication_callback_role_1" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-api-authentication-callback-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.storage_token_kms_signing_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    aws_iam_policy.ipv_public_encryption_key_parameter_policy.arn,
    aws_iam_policy.orch_to_auth_kms_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    local.client_registry_encryption_policy_arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn
  ]
  extra_tags = {
    Service = "orchestration-redirect"
  }
}

module "authentication_callback" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "orchestration-redirect"
  path_part       = var.orch_authentication_callback_enabled ? "orchestration-redirect-auth" : "orchestration-redirect"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    ACCOUNT_INTERVENTION_SERVICE_ACTION_ENABLED = var.account_intervention_service_action_enabled
    ACCOUNT_INTERVENTION_SERVICE_CALL_ENABLED   = var.account_intervention_service_call_enabled
    ACCOUNT_INTERVENTION_SERVICE_URI            = var.account_intervention_service_uri
    AUTHENTICATION_BACKEND_URI                  = "https://${local.di_auth_ext_api_id}-${local.vpce_id}.execute-api.${var.aws_region}.amazonaws.com/${var.environment}/"
    ACCOUNT_INTERVENTIONS_ERROR_METRIC_NAME     = var.account_interventions_error_metric_name
    ENVIRONMENT                                 = var.environment
    IDENTITY_ENABLED                            = var.ipv_api_enabled
    INTERNAl_SECTOR_URI                         = var.internal_sector_uri
    IPV_AUDIENCE                                = var.ipv_audience
    IPV_AUTHORISATION_CALLBACK_URI              = var.ipv_authorisation_callback_uri
    IPV_AUTHORISATION_CLIENT_ID                 = var.ipv_authorisation_client_id
    IPV_AUTHORISATION_URI                       = var.ipv_authorisation_uri
    ORCH_CLIENT_ID                              = var.orch_client_id
    ORCH_TO_AUTH_TOKEN_SIGNING_KEY_ALIAS        = local.orch_to_auth_signing_key_alias_name
    REDIS_KEY                                   = local.redis_key
    TXMA_AUDIT_QUEUE_URL                        = module.oidc_txma_audit.queue_url
    OIDC_API_BASE_URL                           = local.api_base_url
    AUTH_FRONTEND_BASE_URL                      = "https://${local.frontend_fqdn}/"
    ACCOUNT_INTERVENTION_SERVICE_ABORT_ON_ERROR = var.account_intervention_service_abort_on_error
    ACCOUNT_INTERVENTION_SERVICE_CALL_TIMEOUT   = var.account_intervention_service_call_timeout
    STORAGE_TOKEN_SIGNING_KEY_ALIAS             = aws_kms_alias.storage_token_signing_key_alias.name
    SEND_STORAGE_TOKEN_TO_IPV_ENABLED           = var.send_storage_token_to_ipv_enabled
  }

  handler_function_name = "uk.gov.di.authentication.oidc.lambda.AuthenticationCallbackHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  memory_size      = lookup(var.performance_tuning, "orchestration-redirect", local.default_performance_parameters).memory

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.oidc_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.oidc_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.oidc_api_authentication_callback_role_1.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  api_key_required                       = false

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api
  ]
}
