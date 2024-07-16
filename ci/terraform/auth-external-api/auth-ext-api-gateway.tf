data "aws_vpc" "auth_shared_vpc" {
  filter {
    name   = "tag:Name"
    values = ["${var.environment}-shared-vpc"]
  }

}

data "aws_vpc_endpoint" "auth_api_vpc_endpoint" {
  vpc_id       = data.aws_vpc.auth_shared_vpc.id
  service_name = "com.amazonaws.eu-west-2.execute-api"
  tags = {
    environment = var.environment
    terraform   = "core"
  }
}

locals {
  orch_api_vpc_endpoint = var.orch_api_vpc_endpoint_id != "" ? [var.orch_api_vpc_endpoint_id] : []
  api_vpc_endpoints     = concat(local.orch_api_vpc_endpoint, [data.aws_vpc_endpoint.auth_api_vpc_endpoint.id])
}

locals {
  # Define the modules that will be used to create the API
  # The names of the modules are used to refer to the integration_uri when templating openapi.yaml
  endpoint_modules = {
    userinfo = module.auth_userinfo
    token    = module.auth_token
  }
  openapi_spec = templatefile(
    "${path.module}/openapi.yaml",
    {
      endpoint_modules = local.endpoint_modules,
    }
  )
}

module "auth-external-api_gateway" {
  source = "../modules/openapi-api-gateway"

  openapi_spec = local.openapi_spec

  api_gateway_name = "${var.environment}-di-auth-ext-api"
  environment      = var.environment
  tags             = local.default_tags
  vpc_endpoint_ids = local.api_vpc_endpoints

  enable_api_gateway_execution_logging         = var.enable_api_gateway_execution_logging
  enable_api_gateway_execution_request_tracing = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
  cloudwatch_log_retention                     = var.cloudwatch_log_retention
  logging_endpoint_arns                        = var.logging_endpoint_arns
  cloudwatch_encryption_key_arn                = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  access_logging_template                      = local.access_logging_template
}

moved {
  from = aws_api_gateway_rest_api.di_auth_ext_api
  to   = module.auth-external-api_gateway.aws_api_gateway_rest_api.rest_api
}
moved {
  from = aws_api_gateway_usage_plan.di_auth_ext_api_usage_plan
  to   = module.auth-external-api_gateway.aws_api_gateway_usage_plan.api_usage_plan
}
moved {
  from = aws_api_gateway_stage.di_auth_ext_stage
  to   = module.auth-external-api_gateway.aws_api_gateway_stage.stage
}
moved {
  from = aws_api_gateway_method_settings.di_auth_ext_api_logging_settings
  to   = module.auth-external-api_gateway.aws_api_gateway_method_settings.logging_settings
}
moved {
  from = aws_api_gateway_deployment.auth_ext_api_deployment
  to   = module.auth-external-api_gateway.aws_api_gateway_deployment.deployment
}
moved {
  from = aws_cloudwatch_log_group.auth_ext_stage_access_logs
  to   = module.auth-external-api_gateway.aws_cloudwatch_log_group.access_logs
}
moved {
  from = aws_cloudwatch_log_subscription_filter.auth_ext_api_access_log_subscription
  to   = module.auth-external-api_gateway.aws_cloudwatch_log_subscription_filter.stage_access_log_subscription
}
moved {
  from = aws_cloudwatch_log_subscription_filter.auth_ext_api_execution_log_subscription
  to   = module.auth-external-api_gateway.aws_cloudwatch_log_subscription_filter.execution_log_subscription
}

resource "aws_lambda_permission" "auth_ext_api_endpoint_execution_permission" {
  for_each      = local.endpoint_modules
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = each.value.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = each.value.endpoint_lambda_alias.name
  source_arn    = "${module.auth-external-api_gateway.api_gateway_execution_arn}/*/*"
}

moved {
  from = module.auth_userinfo.aws_lambda_permission.endpoint_execution_permission
  to   = aws_lambda_permission.auth_ext_api_endpoint_execution_permission["userinfo"]
}
moved {
  from = module.auth_token.aws_lambda_permission.endpoint_execution_permission
  to   = aws_lambda_permission.auth_ext_api_endpoint_execution_permission["token"]
}

module "dashboard_auth_ext_api" {
  source           = "../modules/dashboards"
  api_gateway_name = module.auth-external-api_gateway.api_gateway_name
  use_localstack   = false
}
