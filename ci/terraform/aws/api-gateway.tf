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

  tags = {
    environment = var.environment
  }
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

  tags = {
    environment = var.environment
  }
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

data "aws_region" "current"{
}

locals {
  api_base_url = var.use_localstack ? "${var.aws_endpoint}/restapis/${aws_api_gateway_rest_api.di_authentication_api.id}/${var.api_deployment_stage_name}/_user_request_" : "https://api.${var.environment}.${var.service_domain_name}"
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      module.authorize.resource_id,
      module.jwks.resource_id,
      module.openid_configuration_discovery.resource_id,
      module.register.resource_id,
      module.send_notification.resource_id,
      module.signup.resource_id,
      module.token.resource_id,
      module.userexists.resource_id,
      module.userinfo.resource_id,
      module.update_profile.resource_id,
      module.verify_code.resource_id,
      module.mfa.resource_id,
      module.auth-code.resource_id,
      module.logout.resource_id,
      module.client-info.resource_id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.authorize,
    module.jwks,
    module.openid_configuration_discovery,
    module.register,
    module.send_notification,
    module.signup,
    module.token,
    module.userexists,
    module.userinfo,
    module.update_profile,
    module.verify_code,
    module.mfa,
    module.auth-code,
    module.logout,
    module.client-info,
  ]
}

resource "aws_api_gateway_stage" "endpoint_stage" {
  deployment_id = aws_api_gateway_deployment.deployment.id
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  stage_name = var.api_deployment_stage_name

  depends_on = [
    module.authorize,
    module.jwks,
    module.openid_configuration_discovery,
    module.register,
    module.send_notification,
    module.signup,
    module.token,
    module.userexists,
    module.userinfo,
    module.update_profile,
    module.verify_code,
    module.mfa,
    module.auth-code,
    module.logout,
    module.client-info,
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
    metrics_enabled        = false
    data_trace_enabled     = true
    logging_level          = "INFO"
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