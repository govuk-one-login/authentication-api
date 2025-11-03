resource "aws_lambda_event_source_mapping" "lambda_sqs_mapping" {
  count                              = 1
  event_source_arn                   = var.email_check_results_sqs_queue_arn
  function_name                      = module.email_check_results_writer_lambda.endpoint_lambda_function.arn
  batch_size                         = 1
  maximum_batching_window_in_seconds = 0

  depends_on = [
    module.email_check_results_writer_lambda,
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

module "email_check_results_writer_lambda" {
  source = "../modules/endpoint-lambda"

  endpoint_name = "email-check-writer"
  handler_environment_variables = {
    ENVIRONMENT = var.environment
  }
  handler_function_name = "uk.gov.di.authentication.utils.lambda.EmailCheckResultWriterHandler::handleRequest"

  memory_size             = 2048
  provisioned_concurrency = var.email_check_results_writer_provisioned_concurrency

  source_bucket           = aws_s3_object.utils_release_zip.bucket
  lambda_zip_file         = aws_s3_object.utils_release_zip.key
  lambda_zip_file_version = aws_s3_object.utils_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = [local.authentication_egress_security_group_id]
  subnet_id          = local.authentication_private_subnet_ids
  environment        = var.environment
  lambda_role_arn    = module.email_check_results_writer_role.arn

  runbook_link                           = "https://govukverify.atlassian.net/wiki/x/NYDnVgE"
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = local.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  depends_on = [module.email_check_results_writer_role]
}
