output "arn" {
  value = aws_lambda_layer_version.lambda_layer.arn
}

output "layer_version" {
  value = aws_lambda_layer_version.lambda_layer.version
}
