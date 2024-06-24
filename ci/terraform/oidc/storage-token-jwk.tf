module "oidc_storage_token_jwk_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-storage-token-jwk-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.storage_token_kms_signing_policy.arn
  ]
}

module "storage_token_jwk" {
  source = "../modules/endpoint-module"

  endpoint_name   = "storage-token-jwk.json"
  path_part       = "storage-token-jwk-auth.json"
  endpoint_method = ["GET"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                     = var.environment
    DOC_APP_TOKEN_SIGNING_KEY_ALIAS = local.doc_app_auth_key_alias_name
    LOCALSTACK_ENDPOINT             = var.use_localstack ? var.localstack_endpoint : null
    STORAGE_TOKEN_SIGNING_KEY_ALIAS = aws_kms_alias.storage_token_signing_key_alias.name
    HEADERS_CASE_INSENSITIVE        = var.use_localstack ? "true" : "false"
  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.StorageTokenJwkHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_resource.wellknown_resource.id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "storage-token-jwk", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "storage-token-jwk", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "storage-token-jwk", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "storage-token-jwk", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.oidc_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.oidc_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  authentication_vpc_arn                 = local.authentication_vpc_arn
  security_group_ids                     = [local.authentication_security_group_id]
  subnet_id                              = local.authentication_private_subnet_ids
  lambda_role_arn                        = module.oidc_storage_token_jwk_role.arn
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
