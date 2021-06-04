resource "aws_api_gateway_rest_api" "di_authentication_api" {
  name = "di-authentication-api-${var.environment}"
}

resource "aws_api_gateway_resource" "wellknown_resource" {
  rest_api_id = aws_api_gateway_rest_api.di_authentication_api.id
  parent_id   = aws_api_gateway_rest_api.di_authentication_api.root_resource_id
  path_part   = ".well-known"
}
