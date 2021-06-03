resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = var.rest_api_id
  parent_id = var.root_resource_id
  path_part = "userinfo"
}

resource "aws_api_gateway_method" "proxyMethod" {
  rest_api_id = var.rest_api_id
  resource_id = aws_api_gateway_resource.proxy.id
  http_method = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda" {
  rest_api_id = var.rest_api_id
  resource_id = aws_api_gateway_method.proxyMethod.resource_id
  http_method = aws_api_gateway_method.proxyMethod.http_method

  integration_http_method = "POST"
  type = "AWS_PROXY"
  uri = aws_lambda_function.userinfo_lambda.invoke_arn
}

resource "aws_api_gateway_method" "proxy_root" {
  rest_api_id = var.rest_api_id
  resource_id = var.root_resource_id
  http_method = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda_root" {
  rest_api_id = var.rest_api_id
  resource_id = aws_api_gateway_method.proxy_root.resource_id
  http_method = aws_api_gateway_method.proxy_root.http_method

  integration_http_method = "POST"
  type = "AWS_PROXY"
  uri = aws_lambda_function.userinfo_lambda.invoke_arn
}

resource "aws_api_gateway_deployment" "apideploy" {
  depends_on = [
    aws_api_gateway_integration.lambda,
    aws_api_gateway_integration.lambda_root,
  ]

  rest_api_id = var.rest_api_id
  stage_name = var.api-deployment-stage-name
}

resource "aws_lambda_permission" "apigw" {
  statement_id = "AllowAPIGatewayInvoke"
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.userinfo_lambda.function_name
  principal = "apigateway.amazonaws.com"

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${var.execution_arn}/*/*"
}

output "base_url_userinfo" {
  value = aws_api_gateway_deployment.apideploy.invoke_url
}