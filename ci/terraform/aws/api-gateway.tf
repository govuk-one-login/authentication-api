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
    aws_api_gateway_deployment.deployment,
  ]
}

resource "aws_api_gateway_base_path_mapping" "api" {
  count = var.use_localstack ? 0 : 1

  api_id      = aws_api_gateway_rest_api.di_authentication_api.id
  stage_name  = aws_api_gateway_stage.endpoint_stage.stage_name
  domain_name = "api.${var.environment}.${var.service_domain_name}"
}