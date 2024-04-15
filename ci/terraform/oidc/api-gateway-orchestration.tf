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
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.orch_frontend_authorizer.id

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

resource "aws_iam_role" "orch_frontend_authorizer_lambda_role" {
  name = "orch-frontend-authorizer-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        },
      }
    ]
  })
}

data "archive_file" "orch_frontend_authorizer_lambda_function" {
  type        = "zip"
  source_file = "${path.module}/orch-frontend/authorizer-lambda.js"
  output_path = "${path.module}/orch-frontend/authorizer-lambda.zip"
}

resource "aws_lambda_function" "orch_frontend_api_gateway_lambda_function_authorizer" {
  function_name                  = "${var.environment}-api-gateway-lambda-function-authorizer"
  handler                        = "${path.module}/orch-frontend/authorizer-lambda.handler"
  role                           = aws_iam_role.orch_frontend_authorizer_lambda_role.arn
  runtime                        = "nodejs20.x"
  memory_size                    = 128
  reserved_concurrent_executions = 1
  timeout                        = 900
  filename                       = data.archive_file.orch_frontend_authorizer_lambda_function.output_path
  source_code_hash               = data.archive_file.orch_frontend_authorizer_lambda_function.output_base64sha256
  environment {
    variables = {
      ENVIRONMENT = var.environment
    }
  }
  tags = {
    Name    = "${var.environment}-api-gateway-lambda-function-authorizer",
    Service = "Orchestration frontend"
    Source  = "govuk-one-login/authentication-api"
    Owner   = "di-orchestration@digital.cabinet-office.gov.uk"
  }
}

resource "aws_api_gateway_authorizer" "orch_frontend_authorizer" {
  name                             = "${var.environment}-orch-frontend-api-gateway-authorizer"
  rest_api_id                      = aws_api_gateway_rest_api.di_authentication_api.id
  authorizer_result_ttl_in_seconds = var.environment == "integration" || var.environment == "production" ? 3600 : 60
  type                             = "REQUEST"
  authorizer_uri                   = "arn:aws:apigateway:${var.aws_region}:lambda:path/2015-03-31/functions/${aws_lambda_function.orch_frontend_api_gateway_lambda_function_authorizer.arn}/invocations"
  identity_source                  = var.environment == "integration" || var.environment == "production" ? "context.identity.apiId" : "context.identity.sourceIp"
}

resource "aws_lambda_permission" "orch_frontend_authorizer_invoke_permission" {
  function_name = aws_lambda_function.orch_frontend_api_gateway_lambda_function_authorizer.arn
  action        = "lambda:InvokeFunction"
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.di_authentication_api.execution_arn}/*/*"
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
