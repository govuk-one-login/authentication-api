resource "aws_api_gateway_rest_api" "di-authentication-api" {
  name = "di-authentication-api-${var.environment}"
}

output "di-authentication-api-id" {
  value = aws_api_gateway_rest_api.di-authentication-api.id
  sensitive = true
}

output "root_resource_id" {
  value = aws_api_gateway_rest_api.di-authentication-api.root_resource_id
  sensitive = true
}

output "execution_arn" {
  value = aws_api_gateway_rest_api.di-authentication-api.execution_arn
  sensitive = true
}