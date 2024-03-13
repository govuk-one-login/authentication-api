output "root_id" {
  value = aws_api_gateway_rest_api.api_gateway_rest_api.id
}

output "stage_id" {
  value = aws_api_gateway_stage.stage.id
}
