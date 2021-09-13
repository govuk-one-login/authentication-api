output "resource_id" {
  value = aws_api_gateway_resource.endpoint_resource.id
}

output "integration_trigger_value" {
  value = jsonencode(aws_api_gateway_integration.endpoint_integration)
}

output "method_trigger_value" {
  value = jsonencode(aws_api_gateway_method.endpoint_method)
}
