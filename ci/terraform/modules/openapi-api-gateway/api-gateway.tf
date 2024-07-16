resource "aws_api_gateway_rest_api" "rest_api" {
  name = var.api_gateway_name

  tags = var.tags

  body = var.openapi_spec
  dynamic "endpoint_configuration" {
    for_each = length(var.vpc_endpoint_ids) > 0 ? [1] : []
    content {
      types            = ["PRIVATE"]
      vpc_endpoint_ids = var.vpc_endpoint_ids
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_rest_api_policy" "rest_api_policy" {
  rest_api_id = aws_api_gateway_rest_api.rest_api.id
  policy      = data.aws_iam_policy_document.rest_api_policy_document.json
}


data "aws_iam_policy_document" "rest_api_policy_document" {
  statement {
    effect = "Allow"

    principals {
      identifiers = ["*"]
      type        = "*"
    }

    actions   = ["execute-api:Invoke"]
    resources = ["${aws_api_gateway_rest_api.rest_api.execution_arn}/*"]
  }

  statement {
    effect = "Deny"

    principals {
      identifiers = ["*"]
      type        = "*"
    }

    actions   = ["execute-api:Invoke"]
    resources = ["${aws_api_gateway_rest_api.rest_api.execution_arn}/*"]

    condition {
      test     = "StringNotEquals"
      values   = var.vpc_endpoint_ids
      variable = "aws:SourceVpce"
    }
  }
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.rest_api.id

  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.rest_api.body))
  }

  depends_on = [
    aws_api_gateway_rest_api_policy.rest_api_policy, # needed for first-time deployment
  ]
  # todo: Check this works properly when the lambda changes
}

resource "aws_api_gateway_stage" "stage" {
  deployment_id         = aws_api_gateway_deployment.deployment.id
  rest_api_id           = aws_api_gateway_rest_api.rest_api.id
  stage_name            = var.environment
  cache_cluster_enabled = false
  xray_tracing_enabled  = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access_logs.arn
    format          = var.access_logging_template
  }

  lifecycle {
    replace_triggered_by = [aws_api_gateway_deployment.deployment.id]
  }

  tags = var.tags
  # checkov:skip=CKV_AWS_51:Client cert authentication is something we might want to consider in the future
  # checkov:skip=CKV_AWS_120:We do not want API caching on this Lambda
}

resource "aws_api_gateway_usage_plan" "api_usage_plan" {
  name = "${var.api_gateway_name}-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.rest_api.id
    stage  = aws_api_gateway_stage.stage.stage_name
  }
  # checkov:skip=CKV_AWS_120:We do not want API caching on this Lambda
}



resource "aws_api_gateway_method_settings" "logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.rest_api.id
  stage_name  = aws_api_gateway_stage.stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = var.enable_api_gateway_execution_request_tracing
    logging_level      = "INFO"
    caching_enabled    = false
  }
  lifecycle {
    replace_triggered_by = [aws_api_gateway_stage.stage.id]
  }
  # checkov:skip=CKV_AWS_225:We do not want API caching on this Lambda
  # checkov:skip=CKV_AWS_308:We do not want API caching on this Lambda
}

resource "aws_cloudwatch_log_group" "access_logs" {
  name              = "${var.api_gateway_name}-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = var.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "stage_access_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.api_gateway_name}-access-logs-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.access_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_log_subscription_filter" "execution_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.api_gateway_name}-execution-log-subscription"
  log_group_name  = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.rest_api.id}/${var.environment}"
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
