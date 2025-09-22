resource "aws_api_gateway_rest_api" "di_authentication_delivery_receipts_api" {
  name = "${var.environment}-di-authentication-delivery-receipts-api"
}

resource "aws_api_gateway_deployment" "delivery_receipts_api_deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_delivery_receipts_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      module.notify_callback.method_trigger_value,
      module.notify_callback.integration_trigger_value,
    ]))
  }


  lifecycle {
    create_before_destroy = true
  }
}

locals {
}

resource "aws_cloudwatch_log_group" "delivery_receipts_api_stage_execution_logs" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.di_authentication_delivery_receipts_api.id}/${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}


resource "aws_cloudwatch_log_subscription_filter" "delivery_receipts_api_execution_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-delivery-receipts-api-execution-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.delivery_receipts_api_stage_execution_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_log_group" "delivery_receipts_stage_access_logs" {
  name              = "${var.environment}-delivery-receipts-api-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}


resource "aws_cloudwatch_log_subscription_filter" "delivery_receipts_api_access_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-delivery-receipts-api-access-logs-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.delivery_receipts_stage_access_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_api_gateway_stage" "endpoint_delivery_receipts_stage" {
  deployment_id = aws_api_gateway_deployment.delivery_receipts_api_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.di_authentication_delivery_receipts_api.id
  stage_name    = var.environment

  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.delivery_receipts_stage_access_logs.arn
    format          = local.access_logging_template
  }

  depends_on = [
    aws_api_gateway_deployment.delivery_receipts_api_deployment,
  ]

  tags = {
    "FMSRegionalPolicy" = "false"
    "CustomPolicy"      = var.api_fms_tag_value
  }

}

resource "aws_api_gateway_method_settings" "api_gateway_delivery_receipts_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_authentication_delivery_receipts_api.id
  stage_name  = aws_api_gateway_stage.endpoint_delivery_receipts_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = false
    logging_level      = "INFO"
  }
  depends_on = [
    aws_api_gateway_stage.endpoint_delivery_receipts_stage
  ]
}
