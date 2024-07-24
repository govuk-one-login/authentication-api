output "resource_id" {
  value = var.create_endpoint ? aws_api_gateway_resource.endpoint_resource[0].id : var.root_resource_id
}

output "integration_trigger_value" {
  value = jsonencode(aws_api_gateway_integration.endpoint_integration)
}

output "method_trigger_value" {
  value = jsonencode(aws_api_gateway_method.endpoint_method)
}

# The following are required for migration to openapi-endpoint-module
output "integration_uri" {
  value = aws_lambda_alias.endpoint_lambda.invoke_arn
}
output "endpoint_lambda_function" {
  value = aws_lambda_function.endpoint_lambda
}
output "endpoint_lambda_alias" {
  value = aws_lambda_alias.endpoint_lambda
}
