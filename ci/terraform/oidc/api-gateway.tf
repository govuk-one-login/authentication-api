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
  name = "${var.environment}-api-gateway-logging-lambda-role"

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

resource "aws_iam_policy" "api_gateway_logging_policy" {
  name        = "${var.environment}-api-gateway-logging"
  path        = "/"
  description = "IAM policy for logging for API Gateway"

  policy = data.aws_iam_policy_document.api_gateway_logging_policy.json
}

resource "aws_iam_role_policy_attachment" "api_gateway_logging_logs" {
  role       = aws_iam_role.api_gateway_logging_iam_role.name
  policy_arn = aws_iam_policy.api_gateway_logging_policy.arn
}

resource "aws_api_gateway_rest_api" "di_authentication_api" {
  name = "${var.environment}-di-authentication-api"

  tags = local.default_tags
}

resource "aws_api_gateway_usage_plan" "di_auth_usage_plan" {
  name = "${var.environment}-di-auth-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.di_authentication_api.id
    stage  = aws_api_gateway_stage.endpoint_stage.stage_name
  }
  depends_on = [
    aws_api_gateway_stage.endpoint_stage,
    aws_api_gateway_rest_api.di_authentication_api,
  ]
}

resource "aws_api_gateway_resource" "wellknown_resource" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = ".well-known"
}

resource "aws_api_gateway_resource" "connect_resource" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = "connect"
}

resource "aws_api_gateway_resource" "register_resource" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_resource.connect_resource.id
  path_part   = "register"
}

data "aws_region" "current" {
}

locals {
  api_base_url = var.use_localstack ? "${var.aws_endpoint}/restapis/${aws_api_gateway_rest_api.di_authentication_api.id}/${var.environment}/_user_request_" : module.dns.oidc_api_url
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      module.auth-code.integration_trigger_value,
      module.auth-code.method_trigger_value,
      module.authorize.integration_trigger_value,
      module.authorize.method_trigger_value,
      module.jwks.integration_trigger_value,
      module.jwks.method_trigger_value,
      module.logout.integration_trigger_value,
      module.logout.method_trigger_value,
      module.openid_configuration_discovery.integration_trigger_value,
      module.openid_configuration_discovery.method_trigger_value,
      var.client_registry_api_enabled ? module.register[0].integration_trigger_value : null,
      var.client_registry_api_enabled ? module.register[0].method_trigger_value : null,
      module.token.integration_trigger_value,
      module.token.method_trigger_value,
      module.trustmarks.integration_trigger_value,
      module.trustmarks.method_trigger_value,
      var.client_registry_api_enabled ? module.update[0].integration_trigger_value : null,
      var.client_registry_api_enabled ? module.update[0].method_trigger_value : null,
      module.userinfo.integration_trigger_value,
      module.userinfo.method_trigger_value,
      module.ipv-callback.integration_trigger_value,
      module.ipv-callback.method_trigger_value,
      module.ipv-capacity.integration_trigger_value,
      module.ipv-capacity.method_trigger_value,
      module.doc-app-callback.integration_trigger_value,
      module.doc-app-callback.method_trigger_value,
      var.use_robots_txt ? aws_api_gateway_integration_response.robots_txt_integration_response[0].response_templates : null,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.auth-code,
    module.authorize,
    module.jwks,
    module.logout,
    module.openid_configuration_discovery,
    module.register,
    module.token,
    module.trustmarks,
    module.update,
    module.userinfo,
    module.ipv-callback,
    module.ipv-capacity,
  ]
}

resource "aws_cloudwatch_log_group" "oidc_stage_execution_logs" {
  count = var.use_localstack ? 0 : 1

  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.di_authentication_api.id}/${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "oidc_api_execution_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-oidc-api-execution-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.oidc_stage_execution_logs[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_log_group" "oidc_stage_access_logs" {
  count = var.use_localstack ? 0 : 1

  name              = "${var.environment}-oidc-api-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "oidc_access_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-oidc-api-access-logs-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.oidc_stage_access_logs[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_log_group" "oidc_waf_logs" {
  count = var.use_localstack ? 0 : 1

  name              = "aws-waf-logs-oidc-${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "oidc_waf_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-oidc-api-waf-logs-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.oidc_waf_logs[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_api_gateway_stage" "endpoint_stage" {
  deployment_id = aws_api_gateway_deployment.deployment.id
  rest_api_id   = aws_api_gateway_rest_api.di_authentication_api.id
  stage_name    = var.environment

  xray_tracing_enabled = true

  dynamic "access_log_settings" {
    for_each = var.use_localstack ? [] : aws_cloudwatch_log_group.oidc_stage_access_logs
    iterator = log_group
    content {
      destination_arn = log_group.value.arn
      format          = local.access_logging_template
    }
  }

  tags = local.default_tags

  depends_on = [
    module.auth-code,
    module.authorize,
    module.jwks,
    module.logout,
    module.openid_configuration_discovery,
    module.register,
    module.token,
    module.trustmarks,
    module.update,
    module.userinfo,
    module.ipv-callback,
    module.ipv-capacity,
    aws_api_gateway_deployment.deployment,
  ]
}

resource "aws_api_gateway_account" "api_gateway_logging_role" {
  cloudwatch_role_arn = aws_iam_role.api_gateway_logging_iam_role.arn

}

resource "aws_api_gateway_method_settings" "api_gateway_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  stage_name  = aws_api_gateway_stage.endpoint_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
    logging_level      = "INFO"
  }
  depends_on = [
    aws_api_gateway_stage.endpoint_stage
  ]
}

resource "aws_api_gateway_base_path_mapping" "api" {
  count = var.use_localstack ? 0 : 1

  api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  stage_name  = aws_api_gateway_stage.endpoint_stage.stage_name
  domain_name = module.dns.oidc_api_fqdn
}

module "dashboard" {
  source           = "../modules/dashboards"
  api_gateway_name = aws_api_gateway_rest_api.di_authentication_api.name
  use_localstack   = var.use_localstack
}

resource "aws_wafv2_web_acl" "wafregional_web_acl_oidc_api" {
  count = var.use_localstack ? 0 : 1
  name  = "${var.environment}-oidc-waf-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    action {
      block {}
    }
    priority = 1
    name     = "${var.environment}-oidc-waf-rate-based-rule"
    statement {
      rate_based_statement {
        limit              = 3600
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${replace(var.environment, "-", "")}OidcWafMaxRequestRate"
      sampled_requests_enabled   = true
    }
  }

  rule {
    override_action {
      none {}
    }
    priority = 2
    name     = "${var.environment}-oidc-common-rule-set"

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        excluded_rule {
          name = "GenericRFI_QUERYARGUMENTS"
        }
        excluded_rule {
          name = "GenericRFI_BODY"
        }
        dynamic "excluded_rule" {
          for_each = var.environment != "production" ? ["1"] : []
          content {
            name = "EC2MetaDataSSRF_BODY"
          }
        }
        dynamic "excluded_rule" {
          for_each = var.environment != "production" ? ["1"] : []
          content {
            name = "EC2MetaDataSSRF_QUERYARGUMENTS"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${replace(var.environment, "-", "")}OidcWafCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    override_action {
      none {}
    }
    priority = 3
    name     = "${var.environment}-oidc-bad-rule-set"

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${replace(var.environment, "-", "")}OidcWafBaduleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${replace(var.environment, "-", "")}OidcWafRules"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "oidc_waf_association" {
  count        = var.use_localstack ? 0 : 1
  resource_arn = aws_api_gateway_stage.endpoint_stage.arn
  web_acl_arn  = aws_wafv2_web_acl.wafregional_web_acl_oidc_api[count.index].arn

  depends_on = [
    aws_api_gateway_stage.endpoint_stage,
    aws_wafv2_web_acl.wafregional_web_acl_oidc_api
  ]
}

resource "aws_wafv2_web_acl_logging_configuration" "waf_logging_config_oidc_api" {
  count                   = var.use_localstack ? 0 : 1
  log_destination_configs = [aws_cloudwatch_log_group.oidc_waf_logs[count.index].arn]
  resource_arn            = aws_wafv2_web_acl.wafregional_web_acl_oidc_api[count.index].arn
  logging_filter {
    default_behavior = "DROP"

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
  depends_on = [
    aws_cloudwatch_log_group.oidc_waf_logs
  ]
}

resource "aws_api_gateway_resource" "robots_txt_resource" {
  count       = var.use_robots_txt ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = "robots.txt"
}

resource "aws_api_gateway_method" "robots_txt_method" {
  count       = var.use_robots_txt ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.robots_txt_resource[0].id
  http_method = "GET"

  depends_on = [
    aws_api_gateway_resource.robots_txt_resource
  ]
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "robots_txt_integration" {
  count       = var.use_robots_txt ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.robots_txt_resource[0].id
  http_method = aws_api_gateway_method.robots_txt_method[0].http_method

  type = "MOCK"

  request_templates = {
    "application/json" = jsonencode(
      {
        statusCode = 200
      }
    )
  }

  depends_on = [
    aws_api_gateway_resource.robots_txt_resource,
    aws_api_gateway_method.robots_txt_method,
  ]
}

resource "aws_api_gateway_method_response" "robots_txt_method_response" {
  count       = var.use_robots_txt ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.robots_txt_resource[0].id
  http_method = aws_api_gateway_method.robots_txt_method[0].http_method
  status_code = 200
  response_models = {
    "text/plain" = "Empty"
  }
  depends_on = [
    aws_api_gateway_resource.robots_txt_resource,
    aws_api_gateway_method.robots_txt_method,
  ]
}

resource "aws_api_gateway_integration_response" "robots_txt_integration_response" {
  count       = var.use_robots_txt ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.robots_txt_resource[0].id
  http_method = aws_api_gateway_method.robots_txt_method[0].http_method

  status_code = aws_api_gateway_method_response.robots_txt_method_response[0].status_code

  response_templates = {
    "text/plain" = <<EOF
User-agent: *
Disallow: /
EOF
  }

  depends_on = [
    aws_api_gateway_resource.robots_txt_resource,
    aws_api_gateway_method.robots_txt_method,
  ]
}