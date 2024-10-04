module "frontend_api_start_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "frontend-api-start-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_authentication_attempt_read_policy.arn,
    aws_iam_policy.dynamo_auth_session_read_policy.arn,
    aws_iam_policy.dynamo_auth_session_write_policy.arn,
    aws_iam_policy.dynamo_auth_session_delete_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    local.client_registry_encryption_policy_arn,
    local.user_credentials_encryption_policy_arn,
    local.user_profile_encryption_policy_arn
  ]
}

module "start" {
  source = "../modules/endpoint-module"

  endpoint_name   = "start"
  path_part       = "start"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    TXMA_AUDIT_QUEUE_URL                    = module.oidc_txma_audit.queue_url
    LOCALSTACK_ENDPOINT                     = var.use_localstack ? var.localstack_endpoint : null
    CUSTOM_DOC_APP_CLAIM_ENABLED            = var.custom_doc_app_claim_enabled
    DOC_APP_DOMAIN                          = var.doc_app_domain
    REDIS_KEY                               = local.redis_key
    ENVIRONMENT                             = var.environment
    DYNAMO_ENDPOINT                         = var.use_localstack ? var.lambda_dynamo_endpoint : null
    HEADERS_CASE_INSENSITIVE                = var.use_localstack ? "true" : "false"
    IDENTITY_ENABLED                        = var.ipv_api_enabled
    INTERNAl_SECTOR_URI                     = var.internal_sector_uri
    AUTHENTICATION_ATTEMPTS_SERVICE_ENABLED = var.authentication_attempts_service_enabled
  }
  handler_function_name = "uk.gov.di.authentication.frontendapi.lambda.StartHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_frontend_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_frontend_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "start", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "start", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "start", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "start", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.frontend_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.frontend_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.frontend_api_start_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags
  api_key_required                       = true

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_frontend_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
  ]
}

module "codedeploy_start" {
  source               = "../modules/codedeploy"
  endpoint_name        = "start"
  environment          = var.environment
  lambda_function_name = module.start.lambda_function_name
  lambda_version       = module.start.lambda_version
  lambda_alias_name    = module.start.lambda_alias_name
  lambda_alias_version = module.start.lambda_alias_version

  skip_canary              = var.skip_canary
  code_deploy_notification = var.code_deploy_notification
}
