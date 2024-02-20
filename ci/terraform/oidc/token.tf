module "oidc_token_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-token"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.oidc_token_kms_signing_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.dynamo_user_read_access_policy.arn,
    aws_iam_policy.dynamo_user_write_access_policy.arn,
    aws_iam_policy.dynamo_client_registry_read_access_policy.arn,
    aws_iam_policy.redis_parameter_policy.arn,
    module.oidc_txma_audit.access_policy_arn,
    local.client_registry_encryption_policy_arn,
    local.user_credentials_encryption_policy_arn,
    local.user_profile_encryption_policy_arn
  ]
}

data "aws_iam_policy_document" "kms_signing_policy_document" {
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = [
      local.id_token_signing_key_arn,
      aws_kms_key.id_token_signing_key_rsa.arn
    ]
  }
}

resource "aws_iam_policy" "oidc_token_kms_signing_policy" {
  name_prefix = "kms-signing-policy"
  path        = "/${var.environment}/oidc-token/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing"

  policy = data.aws_iam_policy_document.kms_signing_policy_document.json
}

module "token" {
  source = "../modules/endpoint-module"

  endpoint_name   = "token"
  path_part       = "token"
  endpoint_method = ["POST"]
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT                    = var.environment
    OIDC_API_BASE_URL              = local.api_base_url
    DYNAMO_ENDPOINT                = var.use_localstack ? var.lambda_dynamo_endpoint : null
    TXMA_AUDIT_QUEUE_URL           = module.oidc_txma_audit.queue_url
    LOCALSTACK_ENDPOINT            = var.use_localstack ? var.localstack_endpoint : null
    REDIS_KEY                      = local.redis_key
    ID_TOKEN_SIGNING_KEY_ALIAS     = local.id_token_signing_key_alias_name
    ID_TOKEN_SIGNING_KEY_RSA_ALIAS = aws_kms_alias.id_token_signing_key_alias.name
    LOCALSTACK_ENDPOINT            = var.use_localstack ? var.localstack_endpoint : null
    HEADERS_CASE_INSENSITIVE       = var.use_localstack ? "true" : "false"
    INTERNAl_SECTOR_URI            = var.internal_sector_uri
  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.TokenHandler::handleRequest"

  rest_api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn    = aws_api_gateway_rest_api.di_authentication_api.execution_arn

  memory_size                 = lookup(var.performance_tuning, "token", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "token", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "token", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "token", local.default_performance_parameters).scaling_trigger

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
  lambda_role_arn                        = module.oidc_token_role.arn
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
