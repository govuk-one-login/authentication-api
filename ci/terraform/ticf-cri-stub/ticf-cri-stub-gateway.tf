locals {
  vpc_environment = var.vpc_environment == null ? var.environment : var.vpc_environment
}

data "aws_vpc" "auth_shared_vpc" {
  filter {
    name   = "tag:Name"
    values = ["${local.vpc_environment}-shared-vpc"]
  }
}

data "aws_vpc_endpoint" "auth_api_vpc_endpoint" {
  vpc_id       = data.aws_vpc.auth_shared_vpc.id
  service_name = "com.amazonaws.eu-west-2.execute-api"
  tags = {
    Environment = local.vpc_environment
    terraform   = "di-infrastructure/core"
  }
}

module "ticf_cri_stub_api_gateway" {
  source = "../modules/private-api-gateway"

  environment      = var.environment
  api_gateway_name = "${var.environment}-di-ticf-cri-stub"

  openapi_spec = jsonencode({
    openapi = "3.0.1"
    info = {
      title = "${var.environment}-di-ticf-cri-stub"
    }
    paths = {
      "/auth" = {
        post = {
          x-amazon-apigateway-integration = {
            type            = "aws_proxy"
            httpMethod      = "POST"
            uri             = module.ticf_cri_stub_lambda.integration_uri
            timeoutInMillis = 29000
          }
        }
      }
    }
  })

  vpc_endpoint_ids = [data.aws_vpc_endpoint.auth_api_vpc_endpoint.id]

  enable_api_gateway_execution_logging         = var.enable_api_gateway_execution_logging
  enable_api_gateway_execution_request_tracing = local.request_tracing_allowed
  cloudwatch_log_retention                     = var.cloudwatch_log_retention
  logging_endpoint_arns                        = var.logging_endpoint_arns
  cloudwatch_encryption_key_arn                = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  access_logging_template                      = local.access_logging_template
}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.ticf_cri_stub_lambda.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = module.ticf_cri_stub_lambda.endpoint_lambda_alias.name

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${module.ticf_cri_stub_api_gateway.api_gateway_execution_arn}/*/*"
}

# State management for the migration to the module
moved {
  from = aws_api_gateway_rest_api.ticf_cri_stub
  to   = module.ticf_cri_stub_api_gateway.module.api-gateway.aws_api_gateway_rest_api.rest_api
}

moved {
  from = aws_api_gateway_rest_api_policy.ticf_cri_stub_policy
  to   = module.ticf_cri_stub_api_gateway.module.api-gateway.aws_api_gateway_rest_api_policy.rest_api_policy[0]
}

moved {
  from = aws_api_gateway_deployment.ticf_cri_stub_deployment
  to   = module.ticf_cri_stub_api_gateway.module.api-gateway.aws_api_gateway_deployment.deployment
}

moved {
  from = aws_api_gateway_stage.ticf_cri_stub_stage
  to   = module.ticf_cri_stub_api_gateway.module.api-gateway.aws_api_gateway_stage.stage
}

moved {
  from = aws_api_gateway_method_settings.ticf_cri_stub_logging_settings[0]
  to   = module.ticf_cri_stub_api_gateway.module.api-gateway.aws_api_gateway_method_settings.logging_settings[0]
}

moved {
  from = aws_cloudwatch_log_group.ticf_cri_stub_stage_access_logs
  to   = module.ticf_cri_stub_api_gateway.module.api-gateway.aws_cloudwatch_log_group.access_logs
}

moved {
  from = aws_cloudwatch_log_subscription_filter.ticf_cri_stub_access_log_subscription
  to   = module.ticf_cri_stub_api_gateway.module.api-gateway.aws_cloudwatch_log_subscription_filter.access_log_subscription
}
