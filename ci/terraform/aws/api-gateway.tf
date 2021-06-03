resource "aws_api_gateway_rest_api" "di-authentication-api" {
  name = format("di-authentication-api-%s", var.environment)
}