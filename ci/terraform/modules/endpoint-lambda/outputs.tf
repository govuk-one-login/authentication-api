output "endpoint_lambda_function" {
  value = aws_lambda_function.endpoint_lambda
}
output "endpoint_lambda_alias" {
  value = aws_lambda_alias.endpoint_lambda
}

output "integration_uri" {
  value = aws_lambda_alias.endpoint_lambda.invoke_arn
}

output "lambda_function_name" {
  value = aws_lambda_function.endpoint_lambda.function_name
}

output "lambda_version" {
  value = aws_lambda_function.endpoint_lambda.version
}

output "lambda_alias_name" {
  value = aws_lambda_alias.endpoint_lambda.name
}

output "lambda_alias_version" {
  value = aws_lambda_alias.endpoint_lambda.function_version
}
output "invoke_arn" {
  value = aws_lambda_alias.endpoint_lambda.invoke_arn
}
