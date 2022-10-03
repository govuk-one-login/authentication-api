module "experian_phone_check_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "experian_phone_check_lambda_role"

  policies_to_attach = [
    aws_iam_policy.user_profile_stream_access.arn,
  ]
}

resource "aws_lambda_function" "experian_phone_check_lambda" {
  function_name = "${var.environment}-experian-phone-check-lambda"
  role          = module.experian_phone_check_lambda_role.arn
  handler       = "uk.gov.di.authentication.utils.lambda.ExperianPhoneCheckHandler::handleRequest"
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

  tags = local.default_tags
}

resource "aws_lambda_event_source_mapping" "user_profile_stream" {
  event_source_arn  = data.aws_dynamodb_table.user_profile.stream_arn
  function_name     = aws_lambda_function.experian_phone_check_lambda.arn
  starting_position = "LATEST"
}

resource "aws_cloudwatch_log_group" "experian_phone_check_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.experian_phone_check_lambda.function_name}"
  kms_key_id        = local.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  tags = local.default_tags

  depends_on = [
    aws_lambda_function.experian_phone_check_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "experian_phone_check_lambda_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_lambda_function.experian_phone_check_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.experian_phone_check_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}