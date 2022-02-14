module "account_management_api_authorizer_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "account-management-api-authorizer-role"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    aws_iam_policy.lambda_kms_policy.arn,
    aws_iam_policy.dynamo_am_user_read_access_policy.arn,
    aws_iam_policy.dynamo_am_client_registry_read_access_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn
  ]
}

resource "aws_lambda_function" "authorizer" {
  function_name = "${var.environment}-api_gateway_authorizer"
  role          = module.account_management_api_authorizer_role.arn
  handler       = "uk.gov.di.accountmanagement.lambda.AuthoriseAccessTokenHandler::handleRequest"
  runtime       = "java11"

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_bucket_object.account_management_api_release_zip.key
  s3_object_version = aws_s3_bucket_object.account_management_api_release_zip.version_id

  publish     = true
  timeout     = 30
  memory_size = 2048
  vpc_config {
    security_group_ids = [local.allow_egress_security_group_id]
    subnet_ids         = local.private_subnet_ids
  }
  environment {
    variables = {
      TOKEN_SIGNING_KEY_ALIAS = data.aws_kms_key.id_token_public_key.key_id
      ENVIRONMENT             = var.environment
    }
  }
  kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
}

resource "aws_api_gateway_authorizer" "di_account_management_api" {
  name                             = "${var.environment}-authorise-access-token"
  rest_api_id                      = aws_api_gateway_rest_api.di_account_management_api.id
  authorizer_uri                   = aws_lambda_alias.authorizer_alias.invoke_arn
  authorizer_credentials           = aws_iam_role.invocation_role.arn
  authorizer_result_ttl_in_seconds = 0
}

resource "aws_lambda_alias" "authorizer_alias" {
  name             = "${var.environment}-authorizer-alias-lambda-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.authorizer.arn
  function_version = aws_lambda_function.authorizer.version
}