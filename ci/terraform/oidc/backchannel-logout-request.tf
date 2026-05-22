module "backchannel_logout_request_role" {
  count       = var.deploy_orch_oidc_lambdas ? 1 : 0
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "backchannel-logout-request-role"

  policies_to_attach = [
    aws_iam_policy.oidc_token_kms_signing_policy.arn,
    aws_iam_policy.back_channel_logout_queue_read_access_policy.arn
  ]
  extra_tags = {
    Service = "backchannel-logout-request"
  }
}
moved {
  from = module.backchannel_logout_request_role
  to   = module.backchannel_logout_request_role[0]
}

resource "aws_lambda_function" "backchannel_logout_request_lambda" {
  count         = var.deploy_orch_oidc_lambdas ? 1 : 0
  function_name = "${var.environment}-backchannel-logout-request-lambda"
  role          = module.backchannel_logout_request_role[0].arn
  handler       = "uk.gov.di.authentication.oidc.lambda.BackChannelLogoutRequestHandler::handleRequest"
  timeout       = 30
  memory_size   = 512
  runtime       = "java17"
  publish       = true

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_object.oidc_api_release_zip.key
  s3_object_version = aws_s3_object.oidc_api_release_zip.version_id

  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  environment {
    variables = merge({
      ENVIRONMENT                      = var.environment
      OIDC_API_BASE_URL                = local.api_base_url
      EXTERNAL_TOKEN_SIGNING_KEY_ALIAS = local.id_token_signing_key_alias_name
    })
  }
  kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn
  tags = {
    Service = "backchannel-logout-request"
  }
}
moved {
  from = aws_lambda_function.backchannel_logout_request_lambda
  to   = aws_lambda_function.backchannel_logout_request_lambda[0]
}

resource "aws_cloudwatch_log_group" "backchannel_logout_request_lambda_log_group" {
  count             = var.deploy_orch_oidc_lambdas ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.backchannel_logout_request_lambda[0].function_name}"
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.backchannel_logout_request_lambda
  ]
}
moved {
  from = aws_cloudwatch_log_group.backchannel_logout_request_lambda_log_group
  to   = aws_cloudwatch_log_group.backchannel_logout_request_lambda_log_group[0]
}


resource "aws_cloudwatch_log_subscription_filter" "backchannel_logout_request_lambda_log_subscription" {
  count           = var.deploy_orch_oidc_lambdas ? length(var.logging_endpoint_arns) : 0
  name            = "${aws_lambda_function.backchannel_logout_request_lambda[0].function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.backchannel_logout_request_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
moved {
  from = aws_cloudwatch_log_subscription_filter.backchannel_logout_request_lambda_log_subscription
  to   = aws_cloudwatch_log_subscription_filter.backchannel_logout_request_lambda_log_subscription[0]
}

resource "aws_lambda_alias" "backchannel_logout_request_lambda_active" {
  count            = var.deploy_orch_oidc_lambdas ? 1 : 0
  name             = "${aws_lambda_function.backchannel_logout_request_lambda[0].function_name}-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.backchannel_logout_request_lambda[0].arn
  function_version = aws_lambda_function.backchannel_logout_request_lambda[0].version
}
moved {
  from = aws_lambda_alias.backchannel_logout_request_lambda_active
  to   = aws_lambda_alias.backchannel_logout_request_lambda_active[0]
}

resource "aws_lambda_event_source_mapping" "backchannel_logout_lambda_sqs_mapping" {
  count            = var.deploy_orch_oidc_lambdas ? 1 : 0
  event_source_arn = aws_sqs_queue.back_channel_logout_queue.arn
  function_name    = aws_lambda_function.backchannel_logout_request_lambda[0].arn

  depends_on = [
    aws_sqs_queue.back_channel_logout_queue,
    aws_lambda_function.backchannel_logout_request_lambda
  ]
  tags = {
    Service = "backchannel-logout-request"
  }
}
moved {
  from = aws_lambda_event_source_mapping.backchannel_logout_lambda_sqs_mapping
  to   = aws_lambda_event_source_mapping.backchannel_logout_lambda_sqs_mapping[0]
}
