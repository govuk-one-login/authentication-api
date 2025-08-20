resource "aws_lambda_event_source_mapping" "lambda_sqs_mapping" {
  count            = 1
  event_source_arn = var.email_check_results_sqs_queue_arn
  function_name    = aws_lambda_function.email_check_results_writer_lambda.arn

  depends_on = [
    aws_lambda_function.email_check_results_writer_lambda,
    aws_iam_policy.email_check_queue_policy,
  ]
}

module "email_check_results_writer_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "${var.environment}-email-check-results-writer"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.email_check_results_writer_dynamo_write_access.arn,
    aws_iam_policy.email_check_queue_policy.arn,
    aws_iam_policy.email_check_sqs_kms_decrypt_policy.arn,
    local.email_check_results_encryption_policy_arn,
  ]
}

resource "aws_lambda_function" "email_check_results_writer_lambda" {
  #checkov:skip=CKV_AWS_116:No DLQ is required for this lambda, as it is SQS driven, and the SQS has a DLQ
  function_name = "${var.environment}-email-check-writer"
  role          = module.email_check_results_writer_role.arn
  handler       = "uk.gov.di.authentication.utils.lambda.EmailCheckResultWriterHandler::handleRequest"
  timeout       = 30
  memory_size   = 512
  runtime       = "java17"
  publish       = true

  s3_bucket         = aws_s3_object.utils_release_zip.bucket
  s3_key            = aws_s3_object.utils_release_zip.key
  s3_object_version = aws_s3_object.utils_release_zip.version_id

  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  vpc_config {
    security_group_ids = [local.authentication_egress_security_group_id]
    subnet_ids         = local.authentication_private_subnet_ids
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      JAVA_TOOL_OPTIONS = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1 '--add-reads=jdk.jfr=ALL-UNNAMED'"
      ENVIRONMENT       = var.environment
    }
  }
  kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
}

resource "aws_lambda_alias" "email_check_results_writer_lambda" {
  name             = replace("${aws_lambda_function.email_check_results_writer_lambda.function_name}-lambda-active", ".", "")
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.email_check_results_writer_lambda.arn
  function_version = aws_lambda_function.email_check_results_writer_lambda.version
}

resource "aws_lambda_provisioned_concurrency_config" "endpoint_lambda_concurrency_config" {
  count = var.email_check_results_writer_provisioned_concurrency == 0 ? 0 : 1

  function_name = aws_lambda_function.email_check_results_writer_lambda.function_name
  qualifier     = aws_lambda_alias.email_check_results_writer_lambda.name

  provisioned_concurrent_executions = var.email_check_results_writer_provisioned_concurrency

  lifecycle {
    ignore_changes = [provisioned_concurrent_executions]
  }

}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name       = "/aws/lambda/${aws_lambda_function.email_check_results_writer_lambda.function_name}"
  kms_key_id = local.cloudwatch_encryption_key_arn
  #checkov:skip=CKV_AWS_338:Cloudwatch logs do not need to be retained for a year, as they are shipped elsewhere (Splunk)
  retention_in_days = var.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.email_check_results_writer_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = replace("${aws_lambda_function.email_check_results_writer_lambda.function_name}-log-subscription-${count.index}", ".", "")
  log_group_name  = aws_cloudwatch_log_group.lambda_log_group.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
