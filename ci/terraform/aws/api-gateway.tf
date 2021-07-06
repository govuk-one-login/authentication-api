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
    aws_api_gateway_deployment.deployment,
  ]
}