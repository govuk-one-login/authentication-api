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
  vpc_endpoint_ids = var.orchestration_vpc_endpoint_id == "" ? [data.aws_vpc_endpoint.auth_api_vpc_endpoint.id] : [data.aws_vpc_endpoint.auth_api_vpc_endpoint.id, var.orchestration_vpc_endpoint_id]
  openapi_spec = {
    openapi = "3.0.1"
    info = {
      title = "${var.environment}-di-interventions-api-stub"
    }
    paths = {
      "/v1/ais/{internalPairwiseId}" = {
        get = {
          parameters = [{
            name     = "internalPairwiseId",
            in       = "path",
            required = true,
            type     = "string"
          }],
          x-amazon-apigateway-integration = {
            type       = "aws_proxy"
            httpMethod = "POST"
            uri        = module.account_interventions_stub_lambda.integration_uri
            requestParameters = {
              "integration.request.path.internalPairwiseId" = "method.request.path.internalPairwiseId"
            }
            timeoutInMillis = 29000
          }
        }
      }
    }
  }
}

module "interventions-api-stub_gateway" {
  source = "../modules/private-api-gateway"

  openapi_spec = jsonencode(local.openapi_spec)

  api_gateway_name = "${var.environment}-di-interventions-api-stub"
  environment      = var.environment
  tags             = local.default_tags

  enable_api_gateway_execution_logging         = var.enable_api_gateway_execution_logging
  enable_api_gateway_execution_request_tracing = local.request_tracing_allowed
  cloudwatch_log_retention                     = var.cloudwatch_log_retention
  logging_endpoint_arns                        = var.logging_endpoint_arns
  cloudwatch_encryption_key_arn                = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  access_logging_template                      = local.access_logging_template

  vpc_endpoint_ids = [data.aws_vpc_endpoint.auth_api_vpc_endpoint.id]
}

moved {
  from = aws_api_gateway_deployment.interventions_api_stub_deployment
  to   = module.interventions-api-stub_gateway.module.api-gateway.aws_api_gateway_deployment.deployment
}

moved {
  from = aws_api_gateway_method_settings.interventions_api_stub_logging_settings[0]
  to   = module.interventions-api-stub_gateway.module.api-gateway.aws_api_gateway_method_settings.logging_settings[0]
}

moved {
  from = aws_api_gateway_rest_api.interventions_api_stub
  to   = module.interventions-api-stub_gateway.module.api-gateway.aws_api_gateway_rest_api.rest_api
}

moved {
  from = aws_api_gateway_rest_api_policy.interventions_api_stub_policy
  to   = module.interventions-api-stub_gateway.module.api-gateway.aws_api_gateway_rest_api_policy.rest_api_policy
}

moved {
  from = aws_api_gateway_stage.interventions_api_stub_stage
  to   = module.interventions-api-stub_gateway.module.api-gateway.aws_api_gateway_stage.stage
}

moved {
  from = aws_cloudwatch_log_group.interventions_api_stub_stage_access_logs
  to   = module.interventions-api-stub_gateway.module.api-gateway.aws_cloudwatch_log_group.access_logs
}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.account_interventions_stub_lambda.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = module.account_interventions_stub_lambda.endpoint_lambda_alias.name

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${module.interventions-api-stub_gateway.api_gateway_execution_arn}/*/*"
}
