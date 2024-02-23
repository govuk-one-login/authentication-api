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
  name = "${var.environment}-account-management-api-gateway-logging-lambda-role"

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

resource "aws_iam_role_policy" "invocation_policy" {
  name = "default"
  role = aws_iam_role.invocation_role.id

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

resource "aws_cloudwatch_log_subscription_filter" "authorizer_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "authorizer-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.lambda_log_group.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_iam_role" "invocation_role" {
  name = "${var.environment}-api_gateway_auth_invocation"
  path = "/"

  assume_role_policy = data.aws_iam_policy_document.api_gateway_can_assume_policy.json
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.authorizer.function_name}"
  tags              = local.default_tags
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.authorizer
  ]
}
moved {
  from = aws_cloudwatch_log_group.lambda_log_group[0]
  to   = aws_cloudwatch_log_group.lambda_log_group

}

resource "aws_iam_policy" "api_gateway_logging_policy" {
  name        = "${var.environment}-account-management-api-gateway-logging"
  path        = "/"
  description = "IAM policy for logging for API Gateway"

  policy = data.aws_iam_policy_document.api_gateway_logging_policy.json
}

resource "aws_iam_role_policy_attachment" "api_gateway_logging_logs" {
  role       = aws_iam_role.api_gateway_logging_iam_role.name
  policy_arn = aws_iam_policy.api_gateway_logging_policy.arn
}

# Define the modules that will be used to create the API
# The names of the modules are used to refer to the integration_uri in the openapi.yaml
locals {
  endpoint_modules = {
    authenticate_module          = module.authenticate
    update-password_module       = module.update_password
    update-email_module          = module.update_email
    send-otp-notification_module = module.send_otp_notification
    delete-account_module        = module.delete_account
    update-phone-number_module   = module.update_phone_number
    create-mfa-methods_module    = module.create-mfa-methods
    delete-mfa-methods_module    = module.delete-mfa-methods
    update-mfa-method_module     = module.update-mfa-method
    retrieve-mfa-methods_module  = module.retrieve-mfa-methods
  }
}
locals {
  template_vars = merge({
    environment            = var.environment
    authorizer_uri         = aws_lambda_alias.authorizer_alias.invoke_arn
    authorizer_credentials = aws_iam_role.invocation_role.arn
  }, local.endpoint_modules)
}

resource "aws_api_gateway_rest_api" "di_account_management_api" {
  name = "${var.environment}-di-account-management-api"

  body = templatefile(
    "${path.module}/openapi.yaml",
    merge({
      environment            = var.environment
      authorizer_uri         = aws_lambda_alias.authorizer_alias.invoke_arn
      authorizer_credentials = aws_iam_role.invocation_role.arn
    }, local.endpoint_modules)
  )

  tags = local.default_tags

  lifecycle {
    create_before_destroy = true
  }
}


resource "aws_lambda_permission" "endpoint_execution_permission" {
  for_each = local.endpoint_modules

  statement_id  = "AllowInvokeFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = each.value.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = each.value.endpoint_lambda_alias.name
  source_arn    = "${aws_api_gateway_rest_api.di_account_management_api.execution_arn}/*/*"
}

locals {
  oidc_api_base_url = "https://${local.oidc_api_fqdn}/"
}

resource "aws_cloudwatch_log_group" "account_management_stage_execution_logs" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.di_account_management_api.id}/${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}
moved {
  from = aws_cloudwatch_log_group.account_management_stage_execution_logs[0]
  to   = aws_cloudwatch_log_group.account_management_stage_execution_logs
}

resource "aws_cloudwatch_log_subscription_filter" "account_management_execution_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-oidc-api-execution-log-subscription"
  log_group_name  = aws_cloudwatch_log_group.account_management_stage_execution_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_log_group" "account_management_access_logs" {
  name              = "${var.environment}-account-management_-api-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}
moved {
  from = aws_cloudwatch_log_group.account_management_access_logs[0]
  to   = aws_cloudwatch_log_group.account_management_access_logs
}

resource "aws_cloudwatch_log_subscription_filter" "account_management_access_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-account-management_-api-access-logs-subscription"
  log_group_name  = aws_cloudwatch_log_group.account_management_access_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_log_group" "account_management_waf_logs" {
  name              = "aws-waf-logs-account-management-${var.environment}"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}
moved {
  from = aws_cloudwatch_log_group.account_management_waf_logs[0]
  to   = aws_cloudwatch_log_group.account_management_waf_logs
}

resource "aws_cloudwatch_log_subscription_filter" "account_management_waf_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-account-management-api-waf-logs-subscription"
  log_group_name  = aws_cloudwatch_log_group.account_management_waf_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_api_gateway_stage" "stage" {
  deployment_id = aws_api_gateway_deployment.deployment.id
  rest_api_id   = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name    = var.environment

  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.account_management_access_logs.arn
    format          = local.access_logging_template
  }

  tags = local.default_tags

  lifecycle {
    replace_triggered_by = [aws_api_gateway_deployment.deployment.id]
  }
}

resource "aws_api_gateway_account" "api_gateway_logging_role" {
  cloudwatch_role_arn = aws_iam_role.api_gateway_logging_iam_role.arn
}

resource "aws_api_gateway_method_settings" "api_gateway_logging_settings" {

  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name  = aws_api_gateway_stage.stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
    logging_level      = "INFO"
  }
  lifecycle {
    replace_triggered_by = [aws_api_gateway_stage.stage.id]
  }
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_account_management_api.id

  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.di_account_management_api.body))
  }
}

resource "aws_api_gateway_base_path_mapping" "api" {
  api_id      = aws_api_gateway_rest_api.di_account_management_api.id
  stage_name  = aws_api_gateway_stage.stage.stage_name
  domain_name = local.account_management_api_fqdn

  lifecycle {
    replace_triggered_by = [aws_api_gateway_stage.stage.id]
  }
}
moved {
  from = aws_api_gateway_base_path_mapping.api[0]
  to   = aws_api_gateway_base_path_mapping.api
}

module "dashboard" {
  source           = "../modules/dashboards"
  api_gateway_name = aws_api_gateway_rest_api.di_account_management_api.name
  use_localstack   = false
}

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
moved {
  from = aws_wafv2_web_acl.wafregional_web_acl_am_api[0]
  to   = aws_wafv2_web_acl.wafregional_web_acl_am_api
}

resource "aws_wafv2_web_acl_association" "waf_association_am_api" {
  resource_arn = aws_api_gateway_stage.stage.arn
  web_acl_arn  = aws_wafv2_web_acl.wafregional_web_acl_am_api.arn

  lifecycle {
    replace_triggered_by = [aws_api_gateway_stage.stage.id]
  }
}
moved {
  from = aws_wafv2_web_acl_association.waf_association_am_api[0]
  to   = aws_wafv2_web_acl_association.waf_association_am_api
}

resource "aws_wafv2_web_acl_logging_configuration" "waf_logging_config_am_api" {
  log_destination_configs = [aws_cloudwatch_log_group.account_management_waf_logs.arn]
  resource_arn            = aws_wafv2_web_acl.wafregional_web_acl_am_api.arn

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
}
moved {
  from = aws_wafv2_web_acl_logging_configuration.waf_logging_config_am_api[0]
  to   = aws_wafv2_web_acl_logging_configuration.waf_logging_config_am_api
}
