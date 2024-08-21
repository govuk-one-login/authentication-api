output "resource_id" {
  value = var.create_endpoint ? aws_api_gateway_resource.endpoint_resource[0].id : var.root_resource_id
}

output "integration_trigger_value" {
  value = jsonencode(aws_api_gateway_integration.endpoint_integration)
}

output "method_trigger_value" {
  value = jsonencode(aws_api_gateway_method.endpoint_method)
}
