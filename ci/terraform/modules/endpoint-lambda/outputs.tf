output "endpoint_lambda_function" {
  value = aws_lambda_function.endpoint_lambda
}
output "endpoint_lambda_alias" {
  value = aws_lambda_alias.endpoint_lambda
}

output "integration_uri" {
  value = aws_lambda_alias.endpoint_lambda.invoke_arn
}

output "invoke_arn" {
  value = aws_lambda_alias.endpoint_lambda.invoke_arn
}

output "function_arn" {
  value = aws_lambda_function.endpoint_lambda.arn
}
