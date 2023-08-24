
module "bulk_user_email_audience_loader_lambda_role" {
  count       = local.deploy_bulk_email_users_count
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "bulk-user-email-audience-loader-lambda-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.bulk_user_email_audience_loader_dynamo_read_access[0].arn,
    aws_iam_policy.bulk_user_email_audience_loader_dynamo_write_access[0].arn,
    aws_iam_policy.bulk_user_email_dynamo_encryption_key_kms_policy[0].arn,
  ]
}

resource "aws_lambda_function" "bulk_user_email_audience_loader_lambda" {
  count                          = local.deploy_bulk_email_users_count
  function_name                  = "${var.environment}-bulk-user-email-audience-loader-lambda"
  role                           = module.bulk_user_email_audience_loader_lambda_role[0].arn
  handler                        = "uk.gov.di.authentication.utils.lambda.BulkUserEmailAudienceLoaderScheduledEventHandler::handleRequest"
  timeout                        = lookup(var.performance_tuning, "bulk-user-email-audience-loader", local.default_performance_parameters).timeout
  memory_size                    = lookup(var.performance_tuning, "bulk-user-email-audience-loader", local.default_performance_parameters).memory
  reserved_concurrent_executions = 1
  runtime                        = "java11"
  tracing_config {
    mode = "Active"
  }
  publish = true

  s3_bucket         = aws_s3_object.utils_release_zip.bucket
  s3_key            = aws_s3_object.utils_release_zip.key
  s3_object_version = aws_s3_object.utils_release_zip.version_id

  kms_key_arn             = local.lambda_env_vars_encryption_kms_key_arn
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  vpc_config {
    security_group_ids = [local.authentication_security_group_id]
    subnet_ids         = local.authentication_subnet_ids
  }

  environment {
    variables = merge(var.notify_template_map, {
      ENVIRONMENT                                  = var.environment
      BULK_USER_EMAIL_BATCH_QUERY_LIMIT            = var.bulk_user_email_batch_query_limit
      BULK_USER_EMAIL_MAX_AUDIENCE_LOAD_USER_COUNT = var.bulk_user_email_max_audience_load_user_count
      BULK_USER_EMAIL_EXCLUDED_TERMS_AND_CONDITIONS = var.bulk_user_email_excluded_terms_and_conditions
      BULK_USER_EMAIL_AUDIENCE_LOADER_LAMBDA_NAME  = local.bulk_user_email_audience_loader_lambda_name
    })
  }

  tags = local.default_tags
  # checkov:skip=CKV_AWS_116:Adding a DLQ would not be useful as the events cannot be replayed.
}


resource "aws_cloudwatch_log_group" "bulk_user_email_audience_loader_lambda_log_group" {
  count = local.deploy_bulk_email_users_count

  name              = "/aws/lambda/${aws_lambda_function.bulk_user_email_audience_loader_lambda[0].function_name}"
  kms_key_id        = local.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  tags = local.default_tags
  # checkov:skip=CKV_AWS_338:Log retention policy is currently 5d not 1 year. To be reviewed.
}

resource "aws_cloudwatch_log_subscription_filter" "bulk_user_email_audience_loader_log_subscription" {
  count           = local.deploy_bulk_email_users_count > 0 ? length(var.logging_endpoint_arns) : 0
  name            = "${aws_lambda_function.bulk_user_email_audience_loader_lambda[0].function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.bulk_user_email_audience_loader_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_event_rule" "bulk_user_email_audience_loader_schedule" {
  count               = local.deploy_bulk_email_users_count
  name                = "${var.environment}-bulk-user-email-audience-loader-schedule"
  is_enabled          = var.bulk_user_email_audience_loader_schedule_enabled
  schedule_expression = var.bulk_user_email_audience_loader_schedule_expression
}

resource "aws_cloudwatch_event_target" "bulk_user_email_audience_loader_schedule_target" {
  count     = local.deploy_bulk_email_users_count
  arn       = aws_lambda_function.bulk_user_email_audience_loader_lambda[0].arn
  rule      = aws_cloudwatch_event_rule.bulk_user_email_audience_loader_schedule[0].name
  target_id = aws_lambda_function.bulk_user_email_audience_loader_lambda[0].version
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_bulk_user_email_audience_loader_lambda" {
  count         = local.deploy_bulk_email_users_count
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.bulk_user_email_audience_loader_lambda[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.bulk_user_email_audience_loader_schedule[0].arn
}
