module "oidc_logout_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-logout-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.oidc_default_id_token_public_key_kms_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    local.client_registry_encryption_policy_arn,
    local.user_credentials_encryption_policy_arn,
    aws_iam_policy.back_channel_logout_queue_write_access_policy.arn
  ]
}

module "logout" {
  source = "../modules/endpoint-module"

  endpoint_name   = "logout"
  path_part       = var.orch_logout_enabled ? "logout-auth" : "logout"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    TXMA_AUDIT_QUEUE_URL                 = module.oidc_txma_audit.queue_url
    LOCALSTACK_ENDPOINT                  = var.use_localstack ? var.localstack_endpoint : null
    REDIS_KEY                            = local.redis_key
    ENVIRONMENT                          = var.environment
    DYNAMO_ENDPOINT                      = var.use_localstack ? var.lambda_dynamo_endpoint : null
    EXTERNAL_TOKEN_SIGNING_KEY_ALIAS     = local.id_token_signing_key_alias_name
    EXTERNAL_TOKEN_SIGNING_KEY_RSA_ALIAS = aws_kms_alias.id_token_signing_key_alias.name
    LOCALSTACK_ENDPOINT                  = var.use_localstack ? var.localstack_endpoint : null
    BACK_CHANNEL_LOGOUT_QUEUE_URI        = aws_sqs_queue.back_channel_logout_queue.id
    INTERNAl_SECTOR_URI                  = var.internal_sector_uri
    OIDC_API_BASE_URL                    = local.api_base_url
    AUTH_FRONTEND_BASE_URL               = "https://${local.frontend_fqdn}/"
  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.LogoutHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  memory_size      = lookup(var.performance_tuning, "logout", local.default_performance_parameters).memory

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.oidc_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.oidc_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn = local.authentication_vpc_arn
  security_group_ids = [
    local.authentication_security_group_id,
    local.authentication_oidc_redis_security_group_id,
  ]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.oidc_logout_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
  ]
}

module "codedeploy_logout" {
  source               = "../modules/codedeploy"
  endpoint_name        = "logout"
  environment          = var.environment
  lambda_function_name = module.logout.lambda_function_name
  lambda_version       = module.logout.lambda_version
  lambda_alias_name    = module.logout.lambda_alias_name
  lambda_alias_version = module.logout.lambda_alias_version
}
