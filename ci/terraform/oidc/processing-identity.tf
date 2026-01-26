module "ipv_processing_identity_role_2" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "ipv-processing-identity-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = concat([
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.pepper_parameter_policy.arn,
    ], var.environment == "production" ? [aws_iam_policy.redis_parameter_policy.arn] : [], [
    module.oidc_txma_audit.access_policy_arn,
    local.account_modifiers_encryption_policy_arn,
    local.client_registry_encryption_policy_arn,
    local.user_credentials_encryption_policy_arn]
  )
  extra_tags = {
    Service = "processing-identity"
  }
}

module "ipv_processing_identity_role_with_orch_session_table_read_write_delete_access_2" {
  count = var.is_orch_stubbed ? 0 : 1

  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "ipv-processing-identity-role-with-orch-session-combined-access"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = concat([
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.pepper_parameter_policy.arn,
    ], var.environment == "production" ? [aws_iam_policy.redis_parameter_policy.arn] : [], [
    module.oidc_txma_audit.access_policy_arn,
    local.account_modifiers_encryption_policy_arn,
    local.client_registry_encryption_policy_arn,
    local.user_credentials_encryption_policy_arn,
    aws_iam_policy.dynamo_orch_session_encryption_key_cross_account_encrypt_decrypt_policy[0].arn,
    aws_iam_policy.dynamo_orch_session_cross_account_read_write_delete_access_policy[0].arn,
    aws_iam_policy.dynamo_orch_client_session_encryption_key_cross_account_decrypt_policy[0].arn,
    aws_iam_policy.dynamo_orch_client_session_cross_account_read_and_delete_access_policy[0].arn,
    aws_iam_policy.dynamo_orch_identity_credentials_cross_account_read_access_policy[0].arn
  ])
}

module "processing-identity" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "processing-identity"
  path_part       = "processing-identity"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    TXMA_AUDIT_QUEUE_URL                        = module.oidc_txma_audit.queue_url
    ENVIRONMENT                                 = var.environment
    REDIS_KEY                                   = var.environment == "production" ? local.redis_key : null
    INTERNAl_SECTOR_URI                         = var.internal_sector_uri
    ACCOUNT_INTERVENTION_SERVICE_ACTION_ENABLED = var.account_intervention_service_action_enabled
    ACCOUNT_INTERVENTION_SERVICE_CALL_ENABLED   = var.account_intervention_service_call_enabled
    ACCOUNT_INTERVENTION_SERVICE_URI            = var.account_intervention_service_uri
    ACCOUNT_INTERVENTION_SERVICE_ABORT_ON_ERROR = var.account_intervention_service_abort_on_error
    ACCOUNT_INTERVENTION_SERVICE_CALL_TIMEOUT   = var.account_intervention_service_call_timeout
    ACCOUNT_INTERVENTIONS_ERROR_METRIC_NAME     = var.account_interventions_error_metric_name
    AUTH_FRONTEND_BASE_URL                      = "https://${local.frontend_fqdn}/"
    OIDC_API_BASE_URL                           = local.api_base_url
    JAVA_TOOL_OPTIONS                           = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1 '--add-reads=jdk.jfr=ALL-UNNAMED'"
    ORCH_DYNAMO_ARN_PREFIX                      = "arn:aws:dynamodb:eu-west-2:${var.orch_account_id}:table/${var.orch_environment}-"
  }
  handler_function_name = "uk.gov.di.authentication.ipv.lambda.ProcessingIdentityHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  memory_size     = lookup(var.performance_tuning, "processing-identity", local.default_performance_parameters).memory
  scaling_trigger = lookup(var.performance_tuning, "processing-identity", local.default_performance_parameters).scaling_trigger
  snapstart       = true

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.ipv_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.ipv_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = concat([
    local.authentication_security_group_id,
  ], var.environment == "production" ? [local.authentication_oidc_redis_security_group_id] : [])

  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = var.is_orch_stubbed ? module.ipv_processing_identity_role_2.arn : module.ipv_processing_identity_role_with_orch_session_table_read_write_delete_access_2[0].arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  api_key_required                       = true
  runbook_link                           = "https://govukverify.atlassian.net/wiki/x/JoD2FwE"

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_frontend_api,
  ]
}
