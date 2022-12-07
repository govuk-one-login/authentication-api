module "bulk_test_user_delete_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "bulk_test_user_delete_lambda_role"

  policies_to_attach = [
    aws_iam_policy.user_profile_dynamo_delete_access.arn,
    aws_iam_policy.user_credentials_dynamo_delete_access.arn,
  ]
}

resource "aws_lambda_function" "bulk_test_user_delete_lambda" {
  count         = var.allow_bulk_test_users ? 1 : 0
  function_name = "${var.environment}-bulk-test-user-delete-lambda"
  role          = module.bulk_test_user_delete_lambda_role.arn
  handler       = "uk.gov.di.authentication.utils.lambda.BulkTestUserDeleteHandler::handleRequest"
  timeout       = 900
  memory_size   = 4096
  runtime       = "java11"
  publish       = true

  s3_bucket         = aws_s3_object.utils_release_zip.bucket
  s3_key            = aws_s3_object.utils_release_zip.key
  s3_object_version = aws_s3_object.utils_release_zip.version_id

  environment {
    variables = merge({
      ENVIRONMENT = var.environment
    })
  }

  tracing_config {
    mode = "Active"
  }

  tags = local.default_tags
}

resource "aws_cloudwatch_log_group" "bulk_test_user_delete_lambda_log_group" {
  count = var.allow_bulk_test_users ? 1 : 0

  name              = "/aws/lambda/${aws_lambda_function.bulk_test_user_delete_lambda[0].function_name}"
  kms_key_id        = local.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  tags = local.default_tags

  depends_on = [
    aws_lambda_function.bulk_test_user_delete_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "bulk_test_user_delete_lambda_log_subscription" {
  count           = var.allow_bulk_test_users ? length(var.logging_endpoint_arns) : 0
  name            = "${aws_lambda_function.bulk_test_user_delete_lambda[count.index].function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.bulk_test_user_delete_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
