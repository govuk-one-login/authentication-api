output "base_url" {
  value = var.use_localstack ? "${var.aws_endpoint}/restapis/${aws_api_gateway_rest_api.di_authentication_api.id}/${var.api_deployment_stage_name}/_user_request_" : aws_api_gateway_stage.endpoint_stage.invoke_url
}

output "api_gateway_root_id" {
  value = aws_api_gateway_rest_api.di_authentication_api.id
}
