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
    aws_api_gateway_deployment.deployment,
  ]
}