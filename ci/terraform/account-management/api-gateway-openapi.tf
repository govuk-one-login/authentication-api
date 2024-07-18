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
      authorizer_credentials = aws_iam_role.authorizer_invocation_role.arn
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

  domain_name                                  = local.account_management_api_fqdn
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
  to   = module.account-management_gateway.aws_api_gateway_rest_api.rest_api
}
# moved {
#   from = aws_api_gateway_usage_plan.di_auth_ext_api_usage_plan
#   to   = module.account-management_gateway.aws_api_gateway_usage_plan.api_usage_plan
# }
moved {
  from = aws_api_gateway_stage.stage
  to   = module.account-management_gateway.aws_api_gateway_stage.stage
}
moved {
  from = aws_api_gateway_method_settings.api_gateway_logging_settings
  to   = module.account-management_gateway.aws_api_gateway_method_settings.logging_settings
}
moved {
  from = aws_api_gateway_deployment.deployment
  to   = module.account-management_gateway.aws_api_gateway_deployment.deployment
}
moved {
  from = aws_cloudwatch_log_group.account_management_access_logs[0]
  to   = module.account-management_gateway.aws_cloudwatch_log_group.access_logs
}
moved {
  from = aws_cloudwatch_log_subscription_filter.account_management_access_log_subscription
  to   = module.account-management_gateway.aws_cloudwatch_log_subscription_filter.stage_access_log_subscription
}
moved {
  from = aws_cloudwatch_log_group.account_management_stage_execution_logs[0]
  to   = module.account-management_gateway.aws_cloudwatch_log_group.execution_logs
}
moved {
  from = aws_cloudwatch_log_subscription_filter.account_management_execution_log_subscription
  to   = module.account-management_gateway.aws_cloudwatch_log_subscription_filter.execution_log_subscription
}
moved {
  from = aws_api_gateway_base_path_mapping.api[0]
  to   = module.account-management_gateway.aws_api_gateway_base_path_mapping.api[0]
}
moved {
  from = aws_wafv2_web_acl_logging_configuration.waf_logging_config_am_api[0]
  to   = module.account-management_gateway.aws_wafv2_web_acl_logging_configuration.waf_logging_configuration[0]
}
moved {
  from = aws_wafv2_web_acl_association.waf_association_am_api[0]
  to   = module.account-management_gateway.aws_wafv2_web_acl_association.waf_association[0]
}
moved {
  from = aws_cloudwatch_log_group.account_management_waf_logs[0]
  to   = module.account-management_gateway.aws_cloudwatch_log_group.waf_logs[0]
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

moved {
  from = module.dashboard
  to   = module.dashboard_account-management_openapi
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

resource "aws_iam_role_policy" "authorizer_invocation_policy" {
  name = "default"
  role = aws_iam_role.authorizer_invocation_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "lambda:InvokeFunction",
      "Effect": "Allow",
      "Resource": [
          "${aws_lambda_alias.authorizer_alias.arn}"
        ]
    }
  ]
}
EOF
}
moved {
  from = aws_iam_role_policy.invocation_policy
  to   = aws_iam_role_policy.authorizer_invocation_policy
}

resource "aws_cloudwatch_log_subscription_filter" "authorizer_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "authorizer-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.authorizer_lambda_log_group.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_iam_role" "authorizer_invocation_role" {
  name = "${var.environment}-api_gateway_auth_invocation"
  path = "/"

  assume_role_policy = data.aws_iam_policy_document.api_gateway_can_assume_policy.json
}

moved {
  from = aws_iam_role.invocation_role
  to   = aws_iam_role.authorizer_invocation_role
}

resource "aws_cloudwatch_log_group" "authorizer_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.authorizer.function_name}"
  tags              = local.default_tags
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention
}
moved {
  from = aws_cloudwatch_log_group.lambda_log_group
  to   = aws_cloudwatch_log_group.authorizer_lambda_log_group
}
