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

resource "aws_api_gateway_api_key" "di_auth_api_key" {
  name = "${var.environment}-di-auth-api-key"
}

resource "aws_api_gateway_usage_plan_key" "di_auth_usage_plan_key" {
  key_id        = aws_api_gateway_api_key.di_auth_api_key.id
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

resource "aws_api_gateway_resource" "oidc_resource" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = "oidc"
}

resource "aws_api_gateway_resource" "clients_resource" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_resource.oidc_resource.id
  path_part   = "clients"
}

data "aws_region" "current" {
}

locals {
  api_base_url = var.use_localstack ? "${var.aws_endpoint}/restapis/${aws_api_gateway_rest_api.di_authentication_api.id}/${var.api_deployment_stage_name}/_user_request_" : "https://api.${var.environment}.${var.service_domain_name}"
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      module.auth-code.integration_trigger_value,
      module.auth-code.method_trigger_value,
      module.authorize.integration_trigger_value,
      module.authorize.method_trigger_value,
      module.client-info.integration_trigger_value,
      module.client-info.method_trigger_value,
      module.jwks.integration_trigger_value,
      module.jwks.method_trigger_value,
      module.login.integration_trigger_value,
      module.login.method_trigger_value,
      module.logout.integration_trigger_value,
      module.logout.method_trigger_value,
      module.mfa.integration_trigger_value,
      module.mfa.method_trigger_value,
      module.openid_configuration_discovery.integration_trigger_value,
      module.openid_configuration_discovery.method_trigger_value,
      module.register.integration_trigger_value,
      module.register.method_trigger_value,
      module.send_notification.integration_trigger_value,
      module.send_notification.method_trigger_value,
      module.signup.integration_trigger_value,
      module.signup.method_trigger_value,
      module.token.integration_trigger_value,
      module.token.method_trigger_value,
      module.update.integration_trigger_value,
      module.update.method_trigger_value,
      module.update_profile.integration_trigger_value,
      module.update_profile.method_trigger_value,
      module.userexists.integration_trigger_value,
      module.userexists.method_trigger_value,
      module.userinfo.integration_trigger_value,
      module.userinfo.method_trigger_value,
      module.verify_code.integration_trigger_value,
      module.verify_code.method_trigger_value,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.auth-code,
    module.authorize,
    module.client-info,
    module.jwks,
    module.login,
    module.logout,
    module.mfa,
    module.openid_configuration_discovery,
    module.register,
    module.send_notification,
    module.signup,
    module.token,
    module.update,
    module.update_profile,
    module.userexists,
    module.userinfo,
    module.verify_code,
  ]
}

resource "aws_api_gateway_stage" "endpoint_stage" {
  deployment_id = aws_api_gateway_deployment.deployment.id
  rest_api_id   = aws_api_gateway_rest_api.di_authentication_api.id
  stage_name    = var.api_deployment_stage_name

  tags = local.default_tags

  depends_on = [
    module.auth-code,
    module.authorize,
    module.client-info,
    module.jwks,
    module.login,
    module.logout,
    module.mfa,
    module.openid_configuration_discovery,
    module.register,
    module.send_notification,
    module.signup,
    module.token,
    module.update,
    module.update_profile,
    module.userexists,
    module.userinfo,
    module.verify_code,
    aws_api_gateway_deployment.deployment,
  ]
}

resource "aws_api_gateway_account" "api_gateway_logging_role" {
  cloudwatch_role_arn = aws_iam_role.api_gateway_logging_iam_role.arn
}

resource "aws_api_gateway_method_settings" "api_gateway_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  stage_name  = var.api_deployment_stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = false
    data_trace_enabled = true
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
  domain_name = "api.${var.environment}.${var.service_domain_name}"
}

module "dashboard" {
  source           = "../modules/dashboards"
  api_gateway_name = aws_api_gateway_rest_api.di_authentication_api.name
  use_localstack   = var.use_localstack
}