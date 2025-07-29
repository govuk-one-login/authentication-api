module "reverification_result_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "reverification-result_role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = concat([
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.ipv_reverification_request_signing_key_policy.arn,
    ], var.environment == "production" ? [aws_iam_policy.redis_parameter_policy.arn] : [], [
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    aws_iam_policy.dynamo_auth_session_read_policy.arn,
    aws_iam_policy.dynamo_id_reverification_state_read_policy.arn
  ])
  extra_tags = {
    Service = "reverification-result"
  }
}

module "reverification_result" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "reverification-result"
  path_part       = "reverification-result"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    TXMA_AUDIT_QUEUE_URL                          = module.oidc_txma_audit.queue_url
    INTERNAl_SECTOR_URI                           = var.internal_sector_uri
    REDIS_KEY                                     = var.environment == "production" ? local.redis_key : null
    IPV_AUDIENCE                                  = var.ipv_audience
    IPV_AUTHORISATION_CALLBACK_URI                = var.ipv_auth_authorize_callback_uri
    IPV_AUTHORISATION_CLIENT_ID                   = var.ipv_auth_authorize_client_id
    ENVIRONMENT                                   = var.environment
    IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS = var.environment == "production" || var.environment == "integration" ? aws_kms_alias.ipv_reverification_request_signing_key_alias.arn : aws_kms_alias.ipv_reverification_request_signing_key_alias_v2.arn
    IPV_BACKEND_URI                               = var.ipv_backend_uri
    USE_STRONGLY_CONSISTENT_READS                 = var.use_strongly_consistent_reads
  }

  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.ReverificationResultHandler::handleRequest"
  runbook_link          = "https://govukverify.atlassian.net/l/cp/LfLKwP4s"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "reverification-result", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "reverification-result", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "reverification-result", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "reverification-result", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.frontend_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.frontend_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = concat([
    local.authentication_egress_security_group_id,
  ], var.environment == "production" ? [local.authentication_oidc_redis_security_group_id] : [])

  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.reverification_result_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  api_key_required                       = true

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_frontend_api
  ]
}
