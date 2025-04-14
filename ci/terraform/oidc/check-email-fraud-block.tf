module "frontend_api_check_email_fraud_block_role" {
  count       = local.deploy_check_email_fraud_block_count
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "frontend-api-check-email-fraud-block-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    local.email_check_results_encryption_policy_arn,
    aws_iam_policy.check_email_fraud_block_read_dynamo_read_access_policy.arn,
    local.client_registry_encryption_policy_arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.dynamo_auth_session_read_policy.arn
  ]
  extra_tags = {
    Service = "check-email-fraud-block"
  }
}

module "check_email_fraud_block" {
  count  = local.deploy_check_email_fraud_block_count
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "check-email-fraud-block"
  path_part       = "check-email-fraud-block"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                   = var.environment
    TXMA_AUDIT_QUEUE_URL          = module.oidc_txma_audit.queue_url
    INTERNAl_SECTOR_URI           = var.internal_sector_uri
    REDIS_KEY                     = local.redis_key
    LOCKOUT_DURATION              = var.lockout_duration
    LOCKOUT_COUNT_TTL             = var.lockout_count_ttl
    SUPPORT_EMAIL_CHECK_ENABLED   = var.support_email_check_enabled
    USE_STRONGLY_CONSISTENT_READS = var.use_strongly_consistent_reads
  }

  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.CheckEmailFraudBlockHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "check-email-fraud-block", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "check-email-fraud-block", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "check-email-fraud-block", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "check-email-fraud-block", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.frontend_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.frontend_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.frontend_api_check_email_fraud_block_role[0].arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  api_key_required                       = true

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_frontend_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
  ]
}
