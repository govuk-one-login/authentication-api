module "api-gateway" {
  source = "../api-gateway"

  environment                                  = var.environment
  api_gateway_name                             = var.api_gateway_name
  extra_tags                                   = var.extra_tags
  openapi_spec                                 = var.openapi_spec
  vpc_endpoint_ids                             = var.vpc_endpoint_ids
  enable_api_gateway_execution_logging         = var.enable_api_gateway_execution_logging
  enable_api_gateway_execution_request_tracing = var.enable_api_gateway_execution_request_tracing
  cloudwatch_log_retention                     = var.cloudwatch_log_retention
  logging_endpoint_arns                        = var.logging_endpoint_arns
  cloudwatch_encryption_key_arn                = var.cloudwatch_encryption_key_arn
  access_logging_template                      = var.access_logging_template
  waf_arns                                     = var.waf_arns
}
