resource "aws_api_gateway_resource" "proxyWellknown" {
  rest_api_id = var.rest_api_id
  parent_id = var.root_resource_id
  path_part = ".well-known/openid-configuration"
}

resource "aws_api_gateway_method" "proxyMethodWellknown" {
  rest_api_id = var.rest_api_id
  resource_id = aws_api_gateway_resource.proxyWellknown.id
  http_method = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambdaWellknown" {
  rest_api_id = var.rest_api_id
  resource_id = aws_api_gateway_method.proxyMethodWellknown.resource_id
  http_method = aws_api_gateway_method.proxyMethodWellknown.http_method

  integration_http_method = "POST"
  type = "AWS_PROXY"
  uri = aws_lambda_function.wellknown_lambda.invoke_arn
}

resource "aws_api_gateway_deployment" "apideployWellknown" {
  depends_on = [
    aws_api_gateway_integration.lambdaWellknown,
  ]

  rest_api_id = var.rest_api_id
  stage_name = var.api-deployment-stage-name
}

resource "aws_lambda_permission" "apigwWellknown" {
  statement_id = "AllowAPIGatewayInvoke"
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.wellknown_lambda.function_name
  principal = "apigateway.amazonaws.com"

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${var.execution_arn}/*/*"
}

output "base_url_wellknown" {
  value = aws_api_gateway_deployment.apideployWellknown.invoke_url
}