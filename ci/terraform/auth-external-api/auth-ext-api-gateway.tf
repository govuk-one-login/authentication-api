data "aws_vpc" "auth_shared_vpc" {
  filter {
    name   = "tag:Name"
    values = ["${var.environment}-shared-vpc"]
  }

}

data "aws_vpc_endpoint" "auth_api_vpc_endpoint" {
  vpc_id       = data.aws_vpc.auth_shared_vpc.id
  service_name = "com.amazonaws.eu-west-2.execute-api"
  tags = {
    environment = var.environment
    terraform   = "core"
  }
}

# Define the modules that will be used to create the API
# The names of the modules are used to refer to the integration_uri in the openapi.yaml
locals {
  endpoint_modules = {
    auth_userinfo_module = module.auth_userinfo
    auth_token_module    = module.auth_token
  }
}

resource "aws_api_gateway_rest_api" "di_auth_ext_api" {
  name = "${var.environment}-di-auth-ext-api"

  body = templatefile(
    "${path.module}/openapi.yaml",
    merge({
      environment = var.environment
    }, local.endpoint_modules)
  )

  tags = local.default_tags
  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = [data.aws_vpc_endpoint.auth_api_vpc_endpoint.id]
  }

  lifecycle {
    create_before_destroy = true
  }
}

data "aws_iam_policy_document" "di_auth_ext_api_policy" {
  statement {
    effect = "Allow"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = [
      "execute-api:Invoke"
    ]
    resources = [
      "${aws_api_gateway_rest_api.di_auth_ext_api.execution_arn}/*"
    ]
  }
  statement {
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = [
      "execute-api:Invoke"
    ]
    resources = [
      "${aws_api_gateway_rest_api.di_auth_ext_api.execution_arn}/*"
    ]
    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpce"
      values   = [data.aws_vpc_endpoint.auth_api_vpc_endpoint.id]
    }
  }

}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  for_each      = local.endpoint_modules
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = each.value.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = each.value.endpoint_lambda_alias.name
  source_arn    = "${aws_api_gateway_rest_api.di_auth_ext_api.execution_arn}/*/*"
}

resource "aws_api_gateway_rest_api_policy" "di_auth_ext_api_policy" {
  rest_api_id = aws_api_gateway_rest_api.di_auth_ext_api.id
  policy      = data.aws_iam_policy_document.di_auth_ext_api_policy.json
}

resource "aws_api_gateway_usage_plan" "di_auth_ext_api_usage_plan" {
  name = "${var.environment}-di-auth-ext-api-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.di_auth_ext_api.id
    stage  = aws_api_gateway_stage.di_auth_ext_stage.stage_name
  }
  # checkov:skip=CKV_AWS_120:We do not want API caching on this Lambda
}

resource "aws_api_gateway_stage" "di_auth_ext_stage" {
  deployment_id         = aws_api_gateway_deployment.auth_ext_api_deployment.id
  rest_api_id           = aws_api_gateway_rest_api.di_auth_ext_api.id
  stage_name            = var.environment
  cache_cluster_enabled = false
  xray_tracing_enabled  = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.auth_ext_stage_access_logs.arn
    format          = local.access_logging_template
  }

  lifecycle {
    replace_triggered_by = [aws_api_gateway_deployment.auth_ext_api_deployment.id]
  }

  tags = local.default_tags
  # checkov:skip=CKV_AWS_51:Client cert authentication is something we might want to consider in the future
  # checkov:skip=CKV_AWS_120:We do not want API caching on this Lambda
}

resource "aws_api_gateway_method_settings" "di_auth_ext_api_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_auth_ext_api.id
  stage_name  = aws_api_gateway_stage.di_auth_ext_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
    logging_level      = "INFO"
    caching_enabled    = false
  }
  lifecycle {
    replace_triggered_by = [aws_api_gateway_stage.di_auth_ext_stage.id]
  }
  # checkov:skip=CKV_AWS_225:We do not want API caching on this Lambda
  # checkov:skip=CKV_AWS_308:We do not want API caching on this Lambda
}

resource "aws_api_gateway_deployment" "auth_ext_api_deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_auth_ext_api.id

  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.di_auth_ext_api.body))
  }
  depends_on = [
    module.auth_userinfo,
    module.auth_token
  ]
}

resource "aws_cloudwatch_log_group" "auth_ext_stage_access_logs" {
  name              = "${var.environment}-auth-ext-api-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "auth_ext_api_access_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-auth-ext-api-access-logs-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.auth_ext_stage_access_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

module "dashboard_auth_ext_api" {
  source           = "../modules/dashboards"
  api_gateway_name = aws_api_gateway_rest_api.di_auth_ext_api.name
  use_localstack   = false
}