resource "aws_api_gateway_rest_api" "di-authentication-api" {
  name = "di-authentication-api-${var.environment}"
}

resource "aws_api_gateway_resource" "wellknown-resource" {
  rest_api_id = aws_api_gateway_rest_api.di-authentication-api.id
  parent_id   = aws_api_gateway_rest_api.di-authentication-api.root_resource_id
  path_part   = ".well-known"
}
