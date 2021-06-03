resource "aws_api_gateway_resource" "proxyToken" {
  rest_api_id = var.rest_api_id
  parent_id = var.root_resource_id
  path_part = "token"
}

resource "aws_api_gateway_method" "proxyMethodToken" {
  rest_api_id = var.rest_api_id
  resource_id = aws_api_gateway_resource.proxyToken.id
  http_method = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambdaToken" {
  rest_api_id = var.rest_api_id
  resource_id = aws_api_gateway_method.proxyMethodToken.resource_id
  http_method = aws_api_gateway_method.proxyMethodToken.http_method

  integration_http_method = "POST"
  type = "AWS_PROXY"
  uri = aws_lambda_function.token_lambda.invoke_arn
}

resource "aws_api_gateway_integration" "lambda_root_token" {
  rest_api_id = var.rest_api_id
  resource_id = aws_api_gateway_method.proxyMethodToken.resource_id
  http_method = aws_api_gateway_method.proxyMethodToken.http_method

  integration_http_method = "POST"
  type = "AWS_PROXY"
  uri = aws_lambda_function.token_lambda.invoke_arn
}

resource "aws_api_gateway_deployment" "apideployToken" {
  depends_on = [
    aws_api_gateway_integration.lambdaToken,
    aws_api_gateway_integration.lambda_root_token,
  ]

  rest_api_id = var.rest_api_id
  stage_name = var.api-deployment-stage-name
}

resource "aws_lambda_permission" "apigwToken" {
  statement_id = "AllowAPIGatewayInvoke"
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.token_lambda.function_name
  principal = "apigateway.amazonaws.com"

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${var.execution_arn}/*/*"
}

output "base_url_token" {
  value = aws_api_gateway_deployment.apideployToken.invoke_url
}