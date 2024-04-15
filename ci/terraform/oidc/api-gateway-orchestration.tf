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

resource "aws_api_gateway_resource" "orch_doc_app_callback_resource" {
  count       = var.orch_doc_app_callback_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = "doc-app-callback"
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
