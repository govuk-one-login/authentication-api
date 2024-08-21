
resource "aws_api_gateway_base_path_mapping" "api" {
  api_id      = module.api-gateway.api_gateway.id
  stage_name  = module.api-gateway.aws_api_gateway_stage.stage_name
  domain_name = var.domain_name
}
