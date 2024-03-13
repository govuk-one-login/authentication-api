resource "aws_wafv2_web_acl" "wafregional_web_acl_oidc_api" {
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
}
locals {
  endpoint_modules = {
    auth-code_module                      = module.auth-code
    authorize_module                      = module.authorize
    jwks_module                           = module.jwks
    storage_token_jwk_module              = module.storage_token_jwk
    logout_module                         = module.logout
    openid_configuration_discovery_module = module.openid_configuration_discovery
    register_module                       = var.client_registry_api_enabled ? module.register[0] : null
    token_module                          = module.token
    trustmarks_module                     = module.trustmarks
    update_module                         = var.client_registry_api_enabled ? module.update[0] : null
    userinfo_module                       = module.userinfo
    ipv-callback_module                   = module.ipv-callback
    ipv-capacity_module                   = module.ipv-capacity
    doc-app-callback_module               = module.doc-app-callback
    authentication_callback_module        = module.authentication_callback
  }
}

module "api-gateway" {
  source = "../modules/openapi-api-gateway-module"

  environment      = var.environment
  endpoint_modules = local.endpoint_modules
  openapi_spec     = file("${path.module}/openapi.yaml")

  resource_prefix       = "oidc"
  short_resource_prefix = "oidc"
  default_tags          = local.default_tags

  cloudwatch_log_retention                     = var.cloudwatch_log_retention
  logging_endpoint_arns                        = var.logging_endpoint_arns
  cloudwatch_encryption_key_arn                = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  access_logging_template                      = local.access_logging_template
  enable_api_gateway_execution_logging         = var.enable_api_gateway_execution_logging
  enable_api_gateway_execution_request_tracing = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
  domain_name                                  = local.oidc_api_fqdn

  waf_arn = aws_wafv2_web_acl.wafregional_web_acl_oidc_api.arn
}

resource "aws_api_gateway_api_key" "client_registry_api_key" {
  count = var.client_registry_api_enabled ? 1 : 0
  name  = "${var.environment}-client-registry-api-key"
}

resource "aws_api_gateway_usage_plan" "di_auth_usage_plan" {
  name = "${var.environment}-di-auth-usage-plan"

  api_stages {
    api_id = module.api-gateway.root_id
    stage  = module.api-gateway.stage_id
  }
}

resource "aws_api_gateway_usage_plan_key" "client_registry_usage_plan_key" {
  count         = var.client_registry_api_enabled ? 1 : 0
  key_id        = aws_api_gateway_api_key.client_registry_api_key[0].id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.di_auth_usage_plan.id
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


locals {
  api_base_url = "https://${local.oidc_api_fqdn}/"
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      var.use_robots_txt ? aws_api_gateway_integration_response.robots_txt_integration_response[0].response_templates : null,
      jsonencode(aws_api_gateway_integration.orch_frontend_nlb_integration),
      jsonencode(aws_api_gateway_method.orch_frontend_proxy_method)
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
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
  authorization = "NONE"

  request_parameters = {
    "method.request.path.proxy" = true
  }
}

data "aws_cloudformation_stack" "orch_frontend_stack" {
  count = var.orch_frontend_api_gateway_integration_enabled ? 1 : 0
  name  = "${var.environment}-orch-frontend"
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
