module "oidc_token_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-token"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = var.use_localstack ? [] : [
    aws_iam_policy.oidc_token_kms_signing_policy[0].arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy[0].arn,
    aws_iam_policy.dynamo_access_policy[0].arn
  ]
}

data "aws_iam_policy_document" "kms_signing_policy_document" {
  count = var.use_localstack ? 0 : 1
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = [
      local.id_token_signing_key_alias_arn
    ]
  }
}

resource "aws_iam_policy" "oidc_token_kms_signing_policy" {
  count       = var.use_localstack ? 0 : 1
  name_prefix = "kms-signing-policy"
  path        = "/${var.environment}/oidc-token/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing"

  policy = data.aws_iam_policy_document.kms_signing_policy_document[0].json
}

module "token" {
  source = "../modules/endpoint-module"

  endpoint_name   = "token"
  path_part       = "token"
  endpoint_method = "POST"
  environment     = var.environment

  handler_environment_variables = {
    ENVIRONMENT              = var.environment
    BASE_URL                 = local.api_base_url
    DYNAMO_ENDPOINT          = var.use_localstack ? var.lambda_dynamo_endpoint : null
    EVENTS_SNS_TOPIC_ARN     = aws_sns_topic.events.arn
    AUDIT_SIGNING_KEY_ALIAS  = local.audit_signing_key_alias_name
    LOCALSTACK_ENDPOINT      = var.use_localstack ? var.localstack_endpoint : null
    REDIS_KEY                = local.redis_key
    TOKEN_SIGNING_KEY_ALIAS  = local.id_token_signing_key_alias_name
    LOCALSTACK_ENDPOINT      = var.use_localstack ? var.localstack_endpoint : null
    HEADERS_CASE_INSENSITIVE = var.use_localstack ? "true" : "false"

  }
  handler_function_name = "uk.gov.di.authentication.oidc.lambda.TokenHandler::handleRequest"

  rest_api_id                            = aws_api_gateway_rest_api.di_authentication_api.id
  root_resource_id                       = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  execution_arn                          = aws_api_gateway_rest_api.di_authentication_api.execution_arn
  lambda_zip_file                        = var.oidc_api_lambda_zip_file
  authentication_vpc_arn                 = local.authentication_vpc_arn
  security_group_id                      = local.authentication_security_group_id
  subnet_id                              = local.authentication_subnet_ids
  lambda_role_arn                        = module.oidc_token_role.arn
  logging_endpoint_enabled               = var.logging_endpoint_enabled
  logging_endpoint_arn                   = var.logging_endpoint_arn
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  default_tags                           = local.default_tags

  keep_lambda_warm             = var.keep_lambdas_warm
  warmer_handler_function_name = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
  warmer_lambda_zip_file       = var.lambda_warmer_zip_file
  warmer_handler_environment_variables = {
    LAMBDA_MIN_CONCURRENCY = var.lambda_min_concurrency
  }

  use_localstack = var.use_localstack

  depends_on = [
    aws_api_gateway_rest_api.di_authentication_api,
    aws_api_gateway_resource.connect_resource,
    aws_api_gateway_resource.wellknown_resource,
  ]
}
