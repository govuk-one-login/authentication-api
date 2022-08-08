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

locals {
  authorizer_memory_size                 = lookup(var.performance_tuning, "authorizer", local.default_performance_parameters).memory
  authorizer_provisioned_concurrency     = lookup(var.performance_tuning, "authorizer", local.default_performance_parameters).concurrency
  authorizer_max_provisioned_concurrency = lookup(var.performance_tuning, "authorizer", local.default_performance_parameters).max_concurrency
  authorizer_scaling_trigger             = lookup(var.performance_tuning, "authorizer", local.default_performance_parameters).scaling_trigger

}

resource "aws_lambda_function" "authorizer" {
  function_name = "${var.environment}-api_gateway_authorizer"
  role          = module.account_management_api_authorizer_role.arn
  handler       = "uk.gov.di.accountmanagement.lambda.AuthoriseAccessTokenHandler::handleRequest"
  runtime       = "java11"

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_bucket_object.account_management_api_release_zip.key
  s3_object_version = aws_s3_bucket_object.account_management_api_release_zip.version_id

  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  publish     = true
  timeout     = 30
  memory_size = local.authorizer_memory_size

  vpc_config {
    security_group_ids = [local.allow_egress_security_group_id]
    subnet_ids         = local.private_subnet_ids
  }
  environment {
    variables = {
      TOKEN_SIGNING_KEY_ALIAS = data.aws_kms_key.id_token_public_key.key_id
      ENVIRONMENT             = var.environment
      JAVA_TOOL_OPTIONS       = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1"
    }
  }
  kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn

  tags = local.default_tags
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

resource "time_sleep" "wait_for_alias_to_reassign" {
  depends_on = [aws_lambda_alias.authorizer_alias]

  triggers = {
    function_name    = aws_lambda_function.authorizer.arn
    function_version = aws_lambda_function.authorizer.version
  }
  create_duration = "60s"
}

resource "aws_lambda_provisioned_concurrency_config" "endpoint_lambda_concurrency_config" {
  count = var.keep_lambdas_warm ? 0 : 1

  function_name = aws_lambda_function.authorizer.function_name
  qualifier     = aws_lambda_alias.authorizer_alias.name

  provisioned_concurrent_executions = local.authorizer_provisioned_concurrency

  depends_on = [
    time_sleep.wait_for_alias_to_reassign
  ]
}

resource "aws_appautoscaling_target" "lambda_target" {
  count = local.authorizer_max_provisioned_concurrency > local.authorizer_provisioned_concurrency ? 1 : 0

  max_capacity       = local.authorizer_max_provisioned_concurrency
  min_capacity       = local.authorizer_provisioned_concurrency
  resource_id        = "function:${aws_lambda_function.authorizer.function_name}:${aws_lambda_alias.authorizer_alias.name}"
  scalable_dimension = "lambda:function:ProvisionedConcurrency"
  service_namespace  = "lambda"
}

resource "aws_appautoscaling_policy" "provisioned-concurrency-policy" {
  count = local.authorizer_max_provisioned_concurrency > local.authorizer_provisioned_concurrency ? 1 : 0

  name               = "LambdaProvisonedConcurrency:${aws_lambda_function.authorizer.function_name}"
  resource_id        = aws_appautoscaling_target.lambda_target[0].resource_id
  scalable_dimension = aws_appautoscaling_target.lambda_target[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.lambda_target[0].service_namespace
  policy_type        = "TargetTrackingScaling"

  target_tracking_scaling_policy_configuration {
    target_value = local.authorizer_scaling_trigger
    predefined_metric_specification {
      predefined_metric_type = "LambdaProvisionedConcurrencyUtilization"
    }
  }
}