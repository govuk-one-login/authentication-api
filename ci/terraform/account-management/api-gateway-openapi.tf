locals {
  # Define the modules that will be used to create the API
  # The names of the modules are used to refer to the integration_uri when templating openapi.yaml
  endpoint_modules = {
    authenticate          = module.authenticate
    update-password       = module.update-password
    update-email          = module.update-email
    delete-account        = module.delete-account
    send-otp-notification = module.send-otp-notification
    update-phone-number   = module.update-phone-number
  }
  openapi_spec = templatefile(
    "${path.module}/openapi.yaml",
    {
      endpoint_modules       = local.endpoint_modules,
      authorizer_uri         = aws_lambda_alias.authorizer_alias.invoke_arn
      authorizer_credentials = aws_iam_role.invocation_role.arn
    }
  )
}

locals {
  oidc_api_base_url = var.use_localstack ? "${var.aws_endpoint}/restapis/${module.account-management_gateway.api_gateway_id}/${var.environment}/_user_request_" : "https://${local.oidc_api_fqdn}/"
}


module "account-management_gateway" {
  source = "../modules/openapi-api-gateway"

  openapi_spec = local.openapi_spec

  api_gateway_name = "${var.environment}-di-account-management-api"
  environment      = var.environment
  tags             = local.default_tags

  enable_api_gateway_execution_logging         = var.enable_api_gateway_execution_logging
  enable_api_gateway_execution_request_tracing = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
  cloudwatch_log_retention                     = var.cloudwatch_log_retention
  logging_endpoint_arns                        = var.logging_endpoint_arns
  cloudwatch_encryption_key_arn                = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  access_logging_template                      = local.access_logging_template

  waf_arns = [
    aws_wafv2_web_acl.wafregional_web_acl_am_api.arn
  ]
}

moved {
  from = aws_api_gateway_rest_api.di_account_management_api
  to   = module.auth-external-api_gateway.aws_api_gateway_rest_api.rest_api
}
# moved {
#   from = aws_api_gateway_usage_plan.di_auth_ext_api_usage_plan
#   to   = module.auth-external-api_gateway.aws_api_gateway_usage_plan.api_usage_plan
# }
moved {
  from = aws_api_gateway_stage.stage
  to   = module.auth-external-api_gateway.aws_api_gateway_stage.stage
}
moved {
  from = aws_api_gateway_method_settings.api_gateway_logging_settings
  to   = module.auth-external-api_gateway.aws_api_gateway_method_settings.logging_settings
}
moved {
  from = aws_api_gateway_deployment.deployment
  to   = module.auth-external-api_gateway.aws_api_gateway_deployment.deployment
}
moved {
  from = aws_cloudwatch_log_group.account_management_access_logs
  to   = module.auth-external-api_gateway.aws_cloudwatch_log_group.access_logs
}
moved {
  from = aws_cloudwatch_log_subscription_filter.account_management_access_log_subscription
  to   = module.auth-external-api_gateway.aws_cloudwatch_log_subscription_filter.stage_access_log_subscription
}
moved {
  from = aws_cloudwatch_log_group.account_management_stage_execution_logs
  to   = module.auth-external-api_gateway.aws_cloudwatch_log_group.execution_logs
}
moved {
  from = aws_cloudwatch_log_subscription_filter.account_management_execution_log_subscription
  to   = module.auth-external-api_gateway.aws_cloudwatch_log_subscription_filter.execution_log_subscription
}
moved {
  from = aws_api_gateway_base_path_mapping.api
  to   = module.account-management_gateway.aws_api_gateway_base_path_mapping.api
}

resource "aws_lambda_permission" "account-management_openapi_endpoint_execution_permission" {
  for_each      = local.endpoint_modules
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = each.value.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = each.value.endpoint_lambda_alias.name
  source_arn    = "${module.account-management_gateway.api_gateway_execution_arn}/*/*"
}

module "dashboard_account-management_openapi" {
  source           = "../modules/dashboards"
  api_gateway_name = module.account-management_gateway.api_gateway_name
  use_localstack   = false
}

## extras

resource "aws_wafv2_web_acl" "wafregional_web_acl_am_api" {
  name  = "${var.environment}-am-waf-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    action {
      block {}
    }
    priority = 1
    name     = "${var.environment}-am-waf-rate-based-rule"
    statement {
      rate_based_statement {
        limit              = 3600
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${replace(var.environment, "-", "")}AMWafMaxRequestRate"
      sampled_requests_enabled   = true
    }
  }

  rule {
    override_action {
      none {}
    }
    priority = 2
    name     = "${var.environment}-am-common-rule-set"

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${replace(var.environment, "-", "")}AMWafCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    override_action {
      none {}
    }
    priority = 3
    name     = "${var.environment}-am-bad-rule-set"

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${replace(var.environment, "-", "")}AmWafBaduleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${replace(var.environment, "-", "")}AMWafRules"
    sampled_requests_enabled   = true
  }
}
