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
          "${aws_lambda_alias.authorizer_alias.arn}"
        ]
    }
  ]
}
EOF
}

resource "aws_iam_role" "invocation_role" {
  name = "${var.environment}-api_gateway_auth_invocation"
  path = "/"

  assume_role_policy = data.aws_iam_policy_document.api_gateway_can_assume_policy.json
}

resource "aws_api_gateway_rest_api" "di_account_management_api" {
  name = "${var.environment}-di-account-management-api"
}

locals {
  oidc_api_base_url = "https://${local.oidc_api_fqdn}/"
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
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.di_account_management_api.id}/${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "account_management_execution_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-oidc-api-execution-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.account_management_stage_execution_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_log_group" "account_management_access_logs" {
  name              = "${var.environment}-account-management_-api-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "account_management_access_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-account-management_-api-access-logs-subscription"
  log_group_name  = aws_cloudwatch_log_group.account_management_access_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_api_gateway_stage" "stage" {
  deployment_id = aws_api_gateway_deployment.deployment.id
  rest_api_id   = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name    = var.environment

  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.account_management_access_logs.arn
    format          = local.access_logging_template
  }

  depends_on = [
    module.update_email,
    module.authenticate,
    aws_api_gateway_deployment.deployment,
  ]

  tags = {
    "FMSRegionalPolicy" = "false"
    "CustomPolicy"      = var.am_api_fms_tag_value
  }
}

resource "aws_api_gateway_method_settings" "api_gateway_logging_settings" {

  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name  = var.environment
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
    logging_level      = "INFO"
  }
  depends_on = [
    aws_api_gateway_stage.stage
  ]
}

resource "aws_api_gateway_base_path_mapping" "api" {
  api_id      = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name  = aws_api_gateway_stage.stage.stage_name
  domain_name = local.account_management_api_fqdn
}

module "dashboard" {
  source           = "../modules/dashboards"
  api_gateway_name = aws_api_gateway_rest_api.di_account_management_api.name
}
