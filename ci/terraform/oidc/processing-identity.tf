module "ipv_processing_identity_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "ipv-processing-identity-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.dynamo_identity_credentials_read_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.pepper_parameter_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    local.account_modifiers_encryption_policy_arn,
    local.client_registry_encryption_policy_arn,
    local.identity_credentials_encryption_policy_arn,
    local.user_credentials_encryption_policy_arn
  ]
}

module "processing-identity" {
  source = "../modules/endpoint-module"

  endpoint_name   = "processing-identity"
  path_part       = "processing-identity"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    DYNAMO_ENDPOINT                             = var.use_localstack ? var.lambda_dynamo_endpoint : null
    TXMA_AUDIT_QUEUE_URL                        = module.oidc_txma_audit.queue_url
    ENVIRONMENT                                 = var.environment
    HEADERS_CASE_INSENSITIVE                    = var.use_localstack ? "true" : "false"
    LOCALSTACK_ENDPOINT                         = var.use_localstack ? var.localstack_endpoint : null
    REDIS_KEY                                   = local.redis_key
    INTERNAl_SECTOR_URI                         = var.internal_sector_uri
    ACCOUNT_INTERVENTION_SERVICE_ACTION_ENABLED = var.account_intervention_service_action_enabled
    ACCOUNT_INTERVENTION_SERVICE_CALL_ENABLED   = var.account_intervention_service_call_enabled
    ACCOUNT_INTERVENTION_SERVICE_URI            = var.account_intervention_service_uri
    ACCOUNT_INTERVENTION_SERVICE_ABORT_ON_ERROR = var.account_intervention_service_abort_on_error
    ACCOUNT_INTERVENTION_SERVICE_CALL_TIMEOUT   = var.account_intervention_service_call_timeout
    AUTH_FRONTEND_BASE_URL                      = "https://${local.frontend_fqdn}/"
    OIDC_API_BASE_URL                           = local.api_base_url
  }
  handler_function_name = "uk.gov.di.authentication.ipv.lambda.ProcessingIdentityHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "processing-identity", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "processing-identity", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "processing-identity", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "processing-identity", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.ipv_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.ipv_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.ipv_processing_identity_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags
  api_key_required                       = true

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_frontend_api,
  ]

  use_localstack = var.use_localstack
}
