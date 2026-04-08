resource "aws_api_gateway_rest_api" "di_authentication_test_services_api" {
  name = "${var.environment}-di-authentication-test-services-api"
}

resource "aws_api_gateway_usage_plan" "di_authentication_test_services_api_usage_plan" {
  name = "${var.environment}-di-authentication-test-services-api-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.di_authentication_test_services_api.id
    stage  = aws_api_gateway_stage.endpoint_test_services_stage.stage_name
  }
  depends_on = [
    aws_api_gateway_stage.endpoint_test_services_stage,
    aws_api_gateway_rest_api.di_authentication_test_services_api,
  ]
}

resource "aws_api_gateway_api_key" "di_authentication_test_services_api_key" {
  name = "${var.environment}-di-authentication-test-services-api-key"
}

resource "aws_api_gateway_usage_plan_key" "di_authentication_test_services_api_usage_plan_key" {
  key_id        = aws_api_gateway_api_key.di_authentication_test_services_api_key.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.di_authentication_test_services_api_usage_plan.id
}

resource "aws_api_gateway_deployment" "test_services_api_deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_test_services_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      module.delete-synthetics-user.method_trigger_value,
      module.delete-synthetics-user.integration_trigger_value,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

locals {
}

resource "aws_cloudwatch_log_group" "test_services_api_stage_execution_logs" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.di_authentication_test_services_api.id}/${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}


resource "aws_cloudwatch_log_subscription_filter" "test_services_api_execution_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-test-services-api-execution-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.test_services_api_stage_execution_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_log_group" "test_services_stage_access_logs" {
  name              = "${var.environment}-test-services-api-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}


resource "aws_cloudwatch_log_subscription_filter" "test_services_api_access_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-test-services-api-access-logs-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.test_services_stage_access_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_api_gateway_stage" "endpoint_test_services_stage" {
  deployment_id = aws_api_gateway_deployment.test_services_api_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.di_authentication_test_services_api.id
  stage_name    = var.environment

  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.test_services_stage_access_logs.arn
    format          = local.access_logging_template
  }

  depends_on = [
    aws_api_gateway_deployment.test_services_api_deployment,
  ]

  tags = {
    "FMSRegionalPolicy" = "false"
    "CustomPolicy"      = var.api_fms_tag_value
  }
}

resource "aws_api_gateway_method_settings" "api_gateway_test_services_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_authentication_test_services_api.id
  stage_name  = aws_api_gateway_stage.endpoint_test_services_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = false
    logging_level      = "INFO"
  }
  depends_on = [
    aws_api_gateway_stage.endpoint_test_services_stage
  ]
}
