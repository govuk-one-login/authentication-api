data "aws_iam_policy_document" "api_gateway_can_assume_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    principals {
      identifiers = [
        "apigateway.amazonaws.com"
      ]
      type = "Service"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role" "api_gateway_logging_iam_role" {
  name = "${var.environment}-account-management-api-gateway-logging-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.api_gateway_can_assume_policy.json

  tags = local.default_tags
}

data "aws_iam_policy_document" "api_gateway_logging_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
      "logs:GetLogEvents",
      "logs:FilterLogEvents",
    ]

    resources = [
      "arn:aws:logs:*:*:*",
    ]
  }
}

resource "aws_api_gateway_authorizer" "di_account_management_api" {
  name                             = "${var.environment}-authorise-access-token"
  rest_api_id                      = aws_api_gateway_rest_api.di_account_management_api.id
  authorizer_uri                   = aws_lambda_alias.authorizer_alias.invoke_arn
  authorizer_credentials           = aws_iam_role.invocation_role.arn
  authorizer_result_ttl_in_seconds = 0
}

resource "aws_iam_role_policy" "invocation_policy" {
  name = "default"
  role = aws_iam_role.invocation_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "lambda:InvokeFunction",
      "Effect": "Allow",
      "Resource": [
          "${aws_lambda_function.authorizer.arn}",
          "${aws_lambda_alias.authorizer_alias.arn}"
        ]
    }
  ]
}
EOF
}

resource "aws_lambda_function" "authorizer" {
  filename         = var.lambda_zip_file
  function_name    = "${var.environment}-api_gateway_authorizer"
  role             = aws_iam_role.lambda_iam_role.arn
  handler          = "uk.gov.di.accountmanagement.lambda.AuthoriseAccessTokenHandler::handleRequest"
  runtime          = "java11"
  source_code_hash = filebase64sha256(var.lambda_zip_file)
  publish          = true
  timeout          = 30
  memory_size      = 2048
  vpc_config {
    security_group_ids = [aws_vpc.account_management_vpc.default_security_group_id]
    subnet_ids         = aws_subnet.account_management_subnets.*.id
  }
  environment {
    variables = {
      TOKEN_SIGNING_KEY_ALIAS = data.aws_kms_key.id_token_public_key.key_id
      ENVIRONMENT             = var.environment
    }
  }
}

resource "aws_cloudwatch_log_subscription_filter" "authorizer_log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "authorizer-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_iam_role" "invocation_role" {
  name = "${var.environment}-api_gateway_auth_invocation"
  path = "/"

  assume_role_policy = data.aws_iam_policy_document.api_gateway_can_assume_policy.json
}

resource "aws_lambda_alias" "authorizer_alias" {
  name             = "${var.environment}-authorizer-alias-lambda-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.authorizer.arn
  function_version = aws_lambda_function.authorizer.version
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  count             = var.use_localstack ? 0 : 1
  name              = "/aws/lambda/${aws_lambda_function.authorizer.function_name}"
  tags              = local.default_tags
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.authorizer
  ]
}

resource "aws_iam_policy" "api_gateway_logging_policy" {
  name        = "${var.environment}-account-management-api-gateway-logging"
  path        = "/"
  description = "IAM policy for logging for API Gateway"

  policy = data.aws_iam_policy_document.api_gateway_logging_policy.json
}

resource "aws_iam_role_policy_attachment" "api_gateway_logging_logs" {
  role       = aws_iam_role.api_gateway_logging_iam_role.name
  policy_arn = aws_iam_policy.api_gateway_logging_policy.arn
}

resource "aws_api_gateway_rest_api" "di_account_management_api" {
  name = "${var.environment}-di-account-management-api"

  tags = local.default_tags
}

data "aws_region" "current" {
}

locals {
  api_base_url = var.use_localstack ? "${var.aws_endpoint}/restapis/${aws_api_gateway_rest_api.di_account_management_api.id}/${var.environment}/_user_request_" : "https://api.${var.environment}.${var.service_domain_name}"
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_account_management_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      module.authenticate.integration_trigger_value,
      module.authenticate.method_trigger_value,
      module.delete_account.integration_trigger_value,
      module.delete_account.method_trigger_value,
      module.update_email.integration_trigger_value,
      module.update_email.method_trigger_value,
      module.update_password.integration_trigger_value,
      module.update_password.method_trigger_value,
      module.update_phone_number.integration_trigger_value,
      module.update_phone_number.method_trigger_value,
      module.send_otp_notification.integration_trigger_value,
      module.send_otp_notification.method_trigger_value,
      aws_lambda_alias.authorizer_alias.function_version
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.update_email,
    module.authenticate,
  ]
}

resource "aws_cloudwatch_log_group" "account_management_stage_execution_logs" {
  count = var.use_localstack ? 0 : 1

  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.di_account_management_api.id}/${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "account_management_execution_log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "${var.environment}-oidc-api-execution-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.account_management_stage_execution_logs[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_cloudwatch_log_group" "account_management_access_logs" {
  count = var.use_localstack ? 0 : 1

  name              = "${var.environment}-account-management_-api-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "account_management_access_log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "${var.environment}-account-management_-api-access-logs-subscription"
  log_group_name  = aws_cloudwatch_log_group.account_management_access_logs[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_api_gateway_stage" "stage" {
  deployment_id = aws_api_gateway_deployment.deployment.id
  rest_api_id   = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name    = var.environment

  dynamic "access_log_settings" {
    for_each = var.use_localstack ? [] : aws_cloudwatch_log_group.account_management_access_logs
    iterator = log_group
    content {
      destination_arn = log_group.value.arn
      format          = local.access_logging_template
    }
  }

  tags = local.default_tags

  depends_on = [
    module.update_email,
    module.authenticate,
    aws_api_gateway_deployment.deployment,
  ]
}

resource "aws_api_gateway_account" "api_gateway_logging_role" {
  cloudwatch_role_arn = aws_iam_role.api_gateway_logging_iam_role.arn
}

resource "aws_api_gateway_method_settings" "api_gateway_logging_settings" {

  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name  = var.environment
  method_path = "*/*"

  settings {
    metrics_enabled    = false
    data_trace_enabled = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
    logging_level      = "INFO"
  }
  depends_on = [
    aws_api_gateway_stage.stage
  ]
}

resource "aws_api_gateway_base_path_mapping" "api" {
  count = var.use_localstack ? 0 : 1

  api_id      = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name  = aws_api_gateway_stage.stage.stage_name
  domain_name = "acct-mgmt-api.${var.environment}.${var.service_domain_name}"
}

module "dashboard" {
  source           = "../modules/dashboards"
  api_gateway_name = aws_api_gateway_rest_api.di_account_management_api.name
  use_localstack   = var.use_localstack
}