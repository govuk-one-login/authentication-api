output "base_url" {
  value = aws_api_gateway_deployment.endpoint_deployment.invoke_url
}

output "lambda_iam_role_arn" {
  value = aws_iam_role.lambda_iam_role.arn
}