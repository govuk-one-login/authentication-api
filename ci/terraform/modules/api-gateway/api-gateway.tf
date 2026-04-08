resource "aws_api_gateway_rest_api" "rest_api" {
  name = var.api_gateway_name

  tags = var.extra_tags

  body = nonsensitive(var.openapi_spec) # Marked nonsensitive so we can see the diff when planning.
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
  # Default allow statement for all traffic
  statement {
    sid    = "AllowAll"
    effect = "Allow"

    principals {
      identifiers = ["*"]
      type        = "*"
    }

    actions   = ["execute-api:Invoke"]
    resources = ["${aws_api_gateway_rest_api.rest_api.execution_arn}/*"]
  }

  dynamic "statement" {
    # Only add this statement if we have VPC endpoint IDs
    for_each = length(var.vpc_endpoint_ids) > 0 ? [1] : []
    content {
      sid    = "EnforceVpcEndpointAccess"
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
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.rest_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_rest_api.rest_api.body,
      aws_api_gateway_rest_api_policy.rest_api_policy.policy
    ]))
  }

  depends_on = [
    aws_api_gateway_rest_api_policy.rest_api_policy, # needed for first-time deployment
  ]
  lifecycle {
    create_before_destroy = true
  }
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

  tags = var.extra_tags
  # checkov:skip=CKV_AWS_51:Client cert authentication is something we might want to consider in the future
  # checkov:skip=CKV2_AWS_51:Client cert authentication is something we might want to consider in the future
  # checkov:skip=CKV_AWS_120:We do not want API caching on this Lambda
}

resource "aws_api_gateway_usage_plan" "api_usage_plan" {
  name = "${var.api_gateway_name}-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.rest_api.id
    stage  = aws_api_gateway_stage.stage.stage_name
  }

  tags = var.extra_tags
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
  name = "${var.api_gateway_name}-access-logs"
  #checkov:skip=CKV_AWS_338:Cloudwatch logs do not need to be retained for a year, as they are shipped elsewhere (Splunk)
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = var.cloudwatch_encryption_key_arn

  tags = var.extra_tags
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

resource "aws_cloudwatch_log_group" "execution_logs" {
  name = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.rest_api.id}/${var.environment}"
  #checkov:skip=CKV_AWS_338:Cloudwatch logs do not need to be retained for a year, as they are shipped elsewhere (Splunk)
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = var.cloudwatch_encryption_key_arn

  tags = var.extra_tags
}

resource "aws_cloudwatch_log_subscription_filter" "execution_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.api_gateway_name}-execution-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.execution_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_wafv2_web_acl_association" "waf_association" {
  count = length(var.waf_arns)

  resource_arn = aws_api_gateway_stage.stage.arn
  web_acl_arn  = var.waf_arns[count.index]
}

resource "aws_cloudwatch_log_group" "waf_logs" {
  count = length(var.waf_arns) > 0 ? 1 : 0

  name = "aws-waf-logs-${var.api_gateway_name}"
  #checkov:skip=CKV_AWS_338:Cloudwatch logs do not need to be retained for a year, as they are shipped elsewhere (Splunk)
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = var.cloudwatch_encryption_key_arn

  tags = var.extra_tags
}

resource "aws_cloudwatch_log_subscription_filter" "waf_log_subscription" {
  count           = length(var.waf_arns) != 0 ? length(var.logging_endpoint_arns) : 0
  name            = "${var.api_gateway_name}-waf-logs-subscription"
  log_group_name  = aws_cloudwatch_log_group.waf_logs[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "waf_logging_configuration" {
  count = length(var.waf_arns)

  log_destination_configs = [aws_cloudwatch_log_group.waf_logs[0].arn]
  resource_arn            = var.waf_arns[count.index]

  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior = "KEEP"

      condition {
        action_condition {
          action = "BLOCK"
        }
      }

      requirement = "MEETS_ANY"
    }
  }
}
