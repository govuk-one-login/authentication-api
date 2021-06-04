resource "aws_api_gateway_resource" "endpoint_resource" {
  rest_api_id = var.rest_api_id
  parent_id   = var.root_resource_id
  path_part   = var.endpoint-name
}

resource "aws_api_gateway_method" "endpoint_method" {
  rest_api_id   = var.rest_api_id
  resource_id   = aws_api_gateway_resource.endpoint_resource.id
  http_method   = var.endpoint-method
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "endpoint_integration" {
  rest_api_id = var.rest_api_id
  resource_id = aws_api_gateway_method.endpoint_method.resource_id
  http_method = aws_api_gateway_method.endpoint_method.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.authorize_lambda.invoke_arn
}

resource "aws_api_gateway_deployment" "endpoint_deployment" {
  rest_api_id = var.rest_api_id
  stage_name  = var.api-deployment-stage-name

  depends_on = [
    aws_api_gateway_integration.endpoint_integration,
  ]
}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorize_lambda.function_name
  principal     = "apigateway.amazonaws.com"

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${var.execution_arn}/*/*"
}

