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
  name           = "${var.environment}-di-authentication-api"
  api_key_source = "HEADER"

  tags = local.default_tags
}

resource "aws_api_gateway_api_key" "client_registry_api_key" {
  count = var.client_registry_api_enabled ? 1 : 0
  name  = "${var.environment}-client-registry-api-key"
}

resource "aws_api_gateway_usage_plan_key" "client_registry_usage_plan_key" {
  count         = var.client_registry_api_enabled ? 1 : 0
  key_id        = aws_api_gateway_api_key.client_registry_api_key[0].id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.di_auth_usage_plan.id
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
  api_base_url = var.use_localstack ? "${var.aws_endpoint}/restapis/${aws_api_gateway_rest_api.di_authentication_api.id}/${var.environment}/_user_request_" : "https://${local.oidc_api_fqdn}/"

  cloudfront_origin_cloaking_header_name = "origin-cloaking-secret"
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
      module.storage_token_jwk.integration_trigger_value,
      module.storage_token_jwk.method_trigger_value,
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
      module.authentication_callback.integration_trigger_value,
      module.authentication_callback.method_trigger_value,
      var.use_robots_txt ? aws_api_gateway_integration_response.robots_txt_integration_response[0].response_templates : null,
      jsonencode(aws_api_gateway_integration.orch_frontend_nlb_integration),
      jsonencode(aws_api_gateway_method.orch_frontend_proxy_method),
      var.orch_openid_configuration_enabled,
      var.orch_trustmark_enabled,
      var.orch_doc_app_callback_enabled,
      var.orch_token_enabled,
      var.orch_jwks_enabled,
      var.orch_authorisation_enabled,
      var.orch_logout_enabled
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.auth-code,
    module.authorize,
    module.jwks,
    module.storage_token_jwk,
    module.logout,
    module.openid_configuration_discovery,
    module.register,
    module.token,
    module.trustmarks,
    module.update,
    module.userinfo,
    module.ipv-callback,
    module.ipv-capacity,
    module.doc-app-callback,
    aws_api_gateway_integration.orch_openid_configuration_integration,
    aws_api_gateway_integration.orch_trustmark_integration,
    aws_api_gateway_integration.orch_doc_app_callback_integration,
    aws_api_gateway_integration.orch_token_integration,
    aws_api_gateway_integration.orch_jwks_integration,
    aws_api_gateway_integration.orch_authorisation_integration,
    aws_api_gateway_integration.orch_logout_integration
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

resource "aws_cloudwatch_log_group" "orch_frontend_authorizer_logs" {
  name              = "/aws/lambda/${aws_lambda_function.orch_frontend_authorizer.function_name}"
  tags              = local.default_tags
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_subscription_filter" "authorizer_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "orch-frontend-authorizer-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.orch_frontend_authorizer_logs.name
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
    module.storage_token_jwk,
    module.logout,
    module.openid_configuration_discovery,
    module.register,
    module.token,
    module.trustmarks,
    module.update,
    module.userinfo,
    module.ipv-callback,
    module.ipv-capacity,
    module.doc-app-callback,
    module.authentication_callback,
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
  domain_name = local.oidc_api_fqdn
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
        limit              = var.environment == "staging" ? 600000 : 3600
        aggregate_key_type = "IP"
        scope_down_statement {
          and_statement {
            statement {
              not_statement {
                statement {
                  byte_match_statement {
                    field_to_match {
                      single_header {
                        name = local.cloudfront_origin_cloaking_header_name
                      }
                    }
                    positional_constraint = "EXACTLY"
                    search_string         = var.oidc_origin_cloaking_header
                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                  }
                }
              }
            }

            statement {
              not_statement {
                statement {
                  byte_match_statement {
                    field_to_match {
                      single_header {
                        name = local.cloudfront_origin_cloaking_header_name
                      }
                    }
                    positional_constraint = "EXACTLY"
                    search_string         = var.previous_oidc_origin_cloaking_header
                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                  }
                }
              }
            }
          }
        }
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

        rule_action_override {
          name = "GenericRFI_QUERYARGUMENTS"
          action_to_use {
            count {}
          }
        }
        rule_action_override {
          name = "GenericRFI_BODY"
          action_to_use {
            count {}
          }
        }

        rule_action_override {
          name = "NoUserAgent_HEADER"
          action_to_use {
            count {}
          }
        }

        rule_action_override {
          name = "EC2MetaDataSSRF_QUERYARGUMENTS"
          action_to_use {
            count {}
          }
        }

        rule_action_override {
          name = "SizeRestrictions_QUERYSTRING"
          action_to_use {
            count {}
          }
        }

        dynamic "rule_action_override" {
          for_each = var.environment != "production" || var.environment != "sandpit" ? ["1"] : []
          content {
            name = "EC2MetaDataSSRF_BODY"
            action_to_use {
              count {}
            }
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

  dynamic "rule" {
    for_each = var.environment == "production" || var.environment == "sandpit" ? ["1"] : []
    content {
      action {
        block {}
      }
      priority = 4
      name     = "${var.environment}-smoke-test-client-exception"

      statement {
        and_statement {
          statement {
            label_match_statement {
              key   = "awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_QueryArguments"
              scope = "LABEL"
            }
          }
          statement {
            not_statement {
              statement {
                byte_match_statement {
                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                  positional_constraint = "EXACTLY"
                  search_string         = data.aws_ssm_parameter.smoke_test_client_id[0].value
                  field_to_match {
                    single_query_argument {
                      name = "client_id"
                    }
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${replace(var.environment, "-", "")}SmokeTestClientExceptionRule"
        sampled_requests_enabled   = true
      }
    }
  }

  rule {
    name     = "default_query_param_limit"
    priority = 5

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          size_constraint_statement {
            comparison_operator = "GT"
            size                = 2048
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }

        statement {
          not_statement {
            statement {
              byte_match_statement {
                positional_constraint = "EXACTLY"
                search_string         = "/authorize"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${replace(var.environment, "-", "")}OidcWafQueryParamSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "extended_query_param_limit"
    priority = 6

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 4096
        field_to_match {
          query_string {}
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${replace(var.environment, "-", "")}OidcWafAuthorizeQueryParamSet"
      sampled_requests_enabled   = true
    }
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${replace(var.environment, "-", "")}OidcWafRules"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "count_not_cloudfront"
    priority = 99

    action {
      count {}
    }

    statement {
      not_statement {
        statement {
          or_statement {
            statement {
              byte_match_statement {
                field_to_match {
                  single_header {
                    name = local.cloudfront_origin_cloaking_header_name
                  }
                }
                positional_constraint = "EXACTLY"
                search_string         = var.oidc_origin_cloaking_header
                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }

            statement {
              byte_match_statement {
                field_to_match {
                  single_header {
                    name = local.cloudfront_origin_cloaking_header_name
                  }
                }
                positional_constraint = "EXACTLY"
                search_string         = var.previous_oidc_origin_cloaking_header
                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }
        }
      }
    }
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

resource "aws_api_gateway_resource" "orch_frontend_resource" {
  count       = var.orch_frontend_api_gateway_integration_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = "orch-frontend"
}

resource "aws_api_gateway_resource" "orch_frontend_resource_proxy" {
  count       = var.orch_frontend_api_gateway_integration_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_resource.orch_frontend_resource[0].id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "orch_frontend_proxy_method" {
  count       = var.orch_frontend_api_gateway_integration_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_frontend_resource_proxy[0].id
  http_method = "ANY"

  depends_on = [
    aws_api_gateway_resource.orch_frontend_resource_proxy
  ]
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.orch_frontend_authorizer.id

  request_parameters = {
    "method.request.path.proxy" = true
  }
}

data "aws_cloudformation_stack" "orch_frontend_stack" {
  count = var.orch_frontend_api_gateway_integration_enabled ? 1 : 0
  name  = "${var.environment}-orch-fe-deploy"
}

locals {
  nlb_dns_name = length(data.aws_cloudformation_stack.orch_frontend_stack) > 0 ? data.aws_cloudformation_stack.orch_frontend_stack[0].outputs["OrchFrontendNlbDnsName"] : null
  nlb_arn      = length(data.aws_cloudformation_stack.orch_frontend_stack) > 0 ? data.aws_cloudformation_stack.orch_frontend_stack[0].outputs["OrchFrontendNlbArn"] : null
}

resource "aws_api_gateway_vpc_link" "orch_frontend_nlb_vpc_link" {
  count       = var.orch_frontend_api_gateway_integration_enabled ? 1 : 0
  name        = "orch-frontend-nlb-vpc-link"
  target_arns = [local.nlb_arn]
}

resource "aws_api_gateway_integration" "orch_frontend_nlb_integration" {
  count       = var.orch_frontend_api_gateway_integration_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_frontend_resource_proxy[0].id
  http_method = aws_api_gateway_method.orch_frontend_proxy_method[0].http_method

  type                    = "HTTP_PROXY"
  uri                     = "http://${local.nlb_dns_name}/orch-frontend/{proxy}"
  integration_http_method = "ANY"

  connection_type = "VPC_LINK"
  connection_id   = aws_api_gateway_vpc_link.orch_frontend_nlb_vpc_link[0].id

  request_parameters = {
    "integration.request.path.proxy" = "method.request.path.proxy"
  }
}

resource "aws_api_gateway_resource" "orch_openid_configuration_resource" {
  count       = var.orch_openid_configuration_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_resource.wellknown_resource.id
  path_part   = "openid-configuration"
  depends_on = [
    aws_api_gateway_resource.wellknown_resource,
    module.openid_configuration_discovery
  ]
}

resource "aws_api_gateway_method" "orch_openid_configuration_method" {
  count       = var.orch_openid_configuration_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_openid_configuration_resource[0].id
  http_method = "GET"

  depends_on = [
    aws_api_gateway_resource.orch_openid_configuration_resource
  ]
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "orch_openid_configuration_integration" {
  count       = var.orch_openid_configuration_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_openid_configuration_resource[0].id
  http_method = aws_api_gateway_method.orch_openid_configuration_method[0].http_method
  depends_on = [
    aws_api_gateway_resource.orch_openid_configuration_resource
  ]
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-2:${var.orch_account_id}:function:${var.orch_openid_configuration_name}:latest/invocations"
}

resource "aws_api_gateway_resource" "orch_trustmark_resource" {
  count       = var.orch_trustmark_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = "trustmark"
  depends_on = [
    module.trustmarks
  ]
}

resource "aws_api_gateway_method" "orch_trustmark_method" {
  count       = var.orch_trustmark_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_trustmark_resource[0].id
  http_method = "GET"

  depends_on = [
    aws_api_gateway_resource.orch_trustmark_resource
  ]
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "orch_trustmark_integration" {
  count       = var.orch_trustmark_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_trustmark_resource[0].id
  http_method = aws_api_gateway_method.orch_trustmark_method[0].http_method
  depends_on = [
    aws_api_gateway_resource.orch_trustmark_resource
  ]
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-2:${var.orch_account_id}:function:${var.orch_trustmark_name}:latest/invocations"
}

resource "aws_api_gateway_resource" "orch_doc_app_callback_resource" {
  count       = var.orch_doc_app_callback_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = "doc-app-callback"
  depends_on = [
    module.doc-app-callback
  ]
}

resource "aws_api_gateway_method" "orch_doc_app_callback_method" {
  count       = var.orch_doc_app_callback_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_doc_app_callback_resource[0].id
  http_method = "GET"

  depends_on = [
    aws_api_gateway_resource.orch_doc_app_callback_resource
  ]
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "orch_doc_app_callback_integration" {
  count       = var.orch_doc_app_callback_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_doc_app_callback_resource[0].id
  http_method = aws_api_gateway_method.orch_doc_app_callback_method[0].http_method
  depends_on = [
    aws_api_gateway_resource.orch_doc_app_callback_resource
  ]
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-2:${var.orch_account_id}:function:${var.orch_doc_app_callback_name}:latest/invocations"
}

resource "aws_api_gateway_resource" "orch_token_resource" {
  count       = var.orch_token_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = "token"
  depends_on = [
    module.token
  ]
}

resource "aws_api_gateway_method" "orch_token_method" {
  count       = var.orch_token_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_token_resource[0].id
  http_method = "POST"

  depends_on = [
    aws_api_gateway_resource.orch_token_resource
  ]
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "orch_token_integration" {
  count       = var.orch_token_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_token_resource[0].id
  http_method = aws_api_gateway_method.orch_token_method[0].http_method
  depends_on = [
    aws_api_gateway_resource.orch_token_resource
  ]
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-2:${var.orch_account_id}:function:${var.orch_token_name}:latest/invocations"
}

resource "aws_api_gateway_resource" "orch_jwks_resource" {
  count       = var.orch_jwks_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_resource.wellknown_resource.id
  path_part   = "jwks.json"
  depends_on = [
    aws_api_gateway_resource.wellknown_resource,
    module.jwks
  ]
}

resource "aws_api_gateway_method" "orch_jwks_method" {
  count       = var.orch_jwks_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_jwks_resource[0].id
  http_method = "GET"

  depends_on = [
    aws_api_gateway_resource.orch_jwks_resource
  ]
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "orch_jwks_integration" {
  count       = var.orch_jwks_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_jwks_resource[0].id
  http_method = aws_api_gateway_method.orch_jwks_method[0].http_method
  depends_on = [
    aws_api_gateway_resource.orch_jwks_resource
  ]
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-2:${var.orch_account_id}:function:${var.orch_jwks_name}:latest/invocations"
}

resource "aws_api_gateway_resource" "orch_authorisation_resource" {
  count       = var.orch_authorisation_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = "authorize"
  depends_on = [
    module.authorize
  ]
}

resource "aws_api_gateway_method" "orch_authorisation_method" {
  for_each    = var.orch_authorisation_enabled ? toset(["GET", "POST"]) : []
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_authorisation_resource[0].id
  http_method = each.key

  depends_on = [
    aws_api_gateway_resource.orch_authorisation_resource
  ]
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "orch_authorisation_integration" {
  for_each    = var.orch_authorisation_enabled ? toset(["GET", "POST"]) : []
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_authorisation_resource[0].id
  http_method = aws_api_gateway_method.orch_authorisation_method[each.key].http_method
  depends_on = [
    aws_api_gateway_resource.orch_authorisation_resource
  ]
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-2:${var.orch_account_id}:function:${var.orch_authorisation_name}:latest/invocations"
}

resource "aws_api_gateway_resource" "orch_logout_resource" {
  count       = var.orch_logout_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = "logout"
  depends_on = [
    module.logout
  ]
}

resource "aws_api_gateway_method" "orch_logout_method" {
  count       = var.orch_logout_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_logout_resource[0].id
  http_method = "GET"

  depends_on = [
    aws_api_gateway_resource.orch_logout_resource
  ]
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "orch_logout_integration" {
  count       = var.orch_logout_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  resource_id = aws_api_gateway_resource.orch_logout_resource[0].id
  http_method = aws_api_gateway_method.orch_logout_method[0].http_method
  depends_on = [
    aws_api_gateway_resource.orch_logout_resource
  ]
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-2:${var.orch_account_id}:function:${var.orch_logout_name}:latest/invocations"
}
