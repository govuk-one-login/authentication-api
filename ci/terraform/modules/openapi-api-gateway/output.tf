output "api_gateway_name" {
  value = aws_api_gateway_rest_api.rest_api.name
}

output "api_gateway_id" {
  value = aws_api_gateway_rest_api.rest_api.id
}

output "api_gateway_execution_arn" {
  value = aws_api_gateway_rest_api.rest_api.execution_arn
}
