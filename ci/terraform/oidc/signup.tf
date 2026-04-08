module "frontend_api_signup_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "frontend-api-signup-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = concat([
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_user_write_access_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    ], var.environment == "production" ? [aws_iam_policy.redis_parameter_policy.arn] : [], [
    aws_iam_policy.dynamo_common_passwords_read_access_policy.arn,
    aws_iam_policy.dynamo_auth_session_read_policy.arn,
    aws_iam_policy.dynamo_auth_session_write_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    local.account_modifiers_encryption_policy_arn,
    local.common_passwords_encryption_policy_arn,
    local.client_registry_encryption_policy_arn,
    local.user_credentials_encryption_policy_arn
  ])
  extra_tags = {
    Service = "signup"
  }
}

module "signup" {
  source = "../modules/endpoint-module-v2"

  endpoint_name   = "signup"
  path_part       = "signup"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                   = var.environment
    TXMA_AUDIT_QUEUE_URL          = module.oidc_txma_audit.queue_url
    REDIS_KEY                     = var.environment == "production" ? local.redis_key : null
    TERMS_CONDITIONS_VERSION      = var.terms_and_conditions
    INTERNAl_SECTOR_URI           = var.internal_sector_uri
    USE_STRONGLY_CONSISTENT_READS = var.use_strongly_consistent_reads
  }
  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.SignUpHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "signup", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "signup", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "signup", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "signup", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.frontend_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.frontend_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = concat([
    local.authentication_security_group_id,
  ], var.environment == "production" ? [local.authentication_oidc_redis_security_group_id] : [])

  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.frontend_api_signup_role.arn
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
