resource "aws_api_gateway_resource" "endpoint_resource" {
  count       = var.create_endpoint ? 1 : 0
  rest_api_id = var.rest_api_id
  parent_id   = var.root_resource_id
  path_part   = var.path_part
}

resource "aws_api_gateway_method" "endpoint_method" {
  for_each    = toset(var.endpoint_method)
  rest_api_id = var.rest_api_id
  resource_id = var.create_endpoint ? aws_api_gateway_resource.endpoint_resource[0].id : var.root_resource_id
  http_method = each.key

  authorization = var.authorizer_id == null ? "NONE" : "CUSTOM"
  authorizer_id = var.authorizer_id

  request_parameters = var.method_request_parameters
  api_key_required   = var.api_key_required
  depends_on = [
    aws_api_gateway_resource.endpoint_resource
  ]
}

resource "aws_api_gateway_integration" "endpoint_integration" {
  for_each           = toset(var.endpoint_method)
  rest_api_id        = var.rest_api_id
  resource_id        = var.create_endpoint ? aws_api_gateway_resource.endpoint_resource[0].id : var.root_resource_id
  http_method        = aws_api_gateway_method.endpoint_method[each.key].http_method
  request_parameters = var.integration_request_parameters

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = module.endpoint_lambda.invoke_arn

  depends_on = [
    aws_api_gateway_resource.endpoint_resource,
    aws_api_gateway_method.endpoint_method,
    module.endpoint_lambda,
  ]
}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.endpoint_lambda.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = module.endpoint_lambda.endpoint_lambda_alias.name

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${var.execution_arn}/*/*"

  depends_on = [
    module.endpoint_lambda
  ]
}
