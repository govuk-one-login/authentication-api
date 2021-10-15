resource "aws_api_gateway_rest_api" "di_authentication_frontend_api" {
  name = "${var.environment}-di-authentication-frontend-api"

  tags = local.default_tags
}

resource "aws_api_gateway_usage_plan" "di_auth_frontend_usage_plan" {
  name = "${var.environment}-di-auth-frontend-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.di_authentication_frontend_api.id
    stage  = aws_api_gateway_stage.endpoint_frontend_stage.stage_name
  }
  depends_on = [
    aws_api_gateway_stage.endpoint_frontend_stage,
    aws_api_gateway_rest_api.di_authentication_frontend_api,
  ]
  throttle_settings {
    burst_limit = 100
    rate_limit  = 100
  }
}

resource "aws_api_gateway_api_key" "di_auth_frontend_api_key" {
  name = "${var.environment}-di-auth-frontend-api-key"
}

resource "aws_api_gateway_usage_plan_key" "di_auth_frontend_usage_plan_key" {
  key_id        = aws_api_gateway_api_key.di_auth_frontend_api_key.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.di_auth_frontend_usage_plan.id
}

locals {
  frontend_api_base_url = var.use_localstack ? "${var.aws_endpoint}/restapis/${aws_api_gateway_rest_api.di_authentication_frontend_api.id}/${var.environment}/_user_request_" : "https://auth.${var.environment}.${var.service_domain_name}"
}

resource "aws_api_gateway_deployment" "frontend_deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_frontend_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      module.client-info.integration_trigger_value,
      module.client-info.method_trigger_value,
      module.login.integration_trigger_value,
      module.login.method_trigger_value,
      module.mfa.integration_trigger_value,
      module.mfa.method_trigger_value,
      module.send_notification.integration_trigger_value,
      module.send_notification.method_trigger_value,
      module.signup.integration_trigger_value,
      module.signup.method_trigger_value,
      module.update_profile.integration_trigger_value,
      module.update_profile.method_trigger_value,
      module.userexists.integration_trigger_value,
      module.userexists.method_trigger_value,
      module.verify_code.integration_trigger_value,
      module.verify_code.method_trigger_value,
      module.reset-password-request.integration_trigger_value,
      module.reset-password-request.method_trigger_value
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.client-info,
    module.login,
    module.mfa,
    module.send_notification,
    module.signup,
    module.update_profile,
    module.userexists,
    module.verify_code,
    module.reset-password-request
  ]
}

resource "aws_cloudwatch_log_group" "frontend_api_stage_execution_logs" {
  count = var.use_localstack ? 0 : 1

  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.di_authentication_frontend_api.id}/${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "frontend_api_execution_log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "${var.environment}-frontend-api-execution-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.frontend_api_stage_execution_logs[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_cloudwatch_log_group" "frontend_stage_access_logs" {
  count = var.use_localstack ? 0 : 1

  name              = "${var.environment}-frontend-api-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "frontend_api_access_log_subscription" {
  count           = var.logging_endpoint_enabled ? 1 : 0
  name            = "${var.environment}-frontend-api-access-logs-subscription"
  log_group_name  = aws_cloudwatch_log_group.frontend_stage_access_logs[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arn
}

resource "aws_api_gateway_stage" "endpoint_frontend_stage" {
  deployment_id = aws_api_gateway_deployment.frontend_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  stage_name    = var.environment

  dynamic "access_log_settings" {
    for_each = var.use_localstack ? [] : aws_cloudwatch_log_group.frontend_stage_access_logs
    iterator = log_group
    content {
      destination_arn = log_group.value.arn
      format          = local.access_logging_template
    }
  }

  tags = local.default_tags

  depends_on = [
    module.client-info,
    module.login,
    module.mfa,
    module.send_notification,
    module.signup,
    module.update_profile,
    module.userexists,
    module.verify_code,
    module.reset-password-request,
    aws_api_gateway_deployment.deployment,
  ]
}

resource "aws_api_gateway_method_settings" "api_gateway_frontend_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  stage_name  = aws_api_gateway_stage.endpoint_frontend_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = false
    data_trace_enabled = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
    logging_level      = "INFO"
  }
  depends_on = [
    aws_api_gateway_stage.endpoint_frontend_stage
  ]
}

resource "aws_api_gateway_base_path_mapping" "frontend_api" {
  count = var.use_localstack ? 0 : 1

  api_id      = aws_api_gateway_rest_api.di_authentication_frontend_api.id
  stage_name  = aws_api_gateway_stage.endpoint_frontend_stage.stage_name
  domain_name = "auth.${var.environment}.${var.service_domain_name}"
}

module "dashboard_frontend_api" {
  source           = "../modules/dashboards"
  api_gateway_name = aws_api_gateway_rest_api.di_authentication_frontend_api.name
  use_localstack   = var.use_localstack
}