output "api_gateway_name" {
  value = module.api-gateway.api_gateway_name
}

output "api_gateway_id" {
  value = module.api-gateway.api_gateway_id
}

output "api_gateway_execution_arn" {
  value = module.api-gateway.api_gateway_execution_arn
}

output "api_gateway_stage_name" {
  value = module.api-gateway.aws_api_gateway_stage.stage_name
}
