output "resource_id" {
  value = var.create_endpoint ? aws_api_gateway_resource.endpoint_resource[0].id : var.root_resource_id
}

output "integration_trigger_value" {
  value = jsonencode(aws_api_gateway_integration.endpoint_integration)
}

output "method_trigger_value" {
  value = jsonencode(aws_api_gateway_method.endpoint_method)
}

# The following are required for migration to openapi
output "integration_uri" {
  value = module.endpoint_lambda.integration_uri
}
output "endpoint_lambda_function" {
  value = module.endpoint_lambda.endpoint_lambda_function
}
output "endpoint_lambda_alias" {
  value = module.endpoint_lambda.endpoint_lambda_alias
}
output "invoke_arn" {
  value = module.endpoint_lambda.invoke_arn
}
