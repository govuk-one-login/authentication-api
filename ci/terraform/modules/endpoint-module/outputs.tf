output "resource_id" {
  value = var.create_endpoint ? aws_api_gateway_resource.endpoint_resource[0].id : var.root_resource_id
}

output "integration_trigger_value" {
  value = jsonencode(aws_api_gateway_integration.endpoint_integration)
}

output "method_trigger_value" {
  value = jsonencode(aws_api_gateway_method.endpoint_method)
}

output "lambda_function_name" {
  value = aws_lambda_function.endpoint_lambda.function_name
}

output "lambda_version" {
  value = aws_lambda_function.endpoint_lambda.version
}

output "lambda_alias_name" {
  value = aws_lambda_alias.endpoint_lambda.name
}

output "lambda_alias_version" {
  value = aws_lambda_alias.endpoint_lambda.function_version
}
