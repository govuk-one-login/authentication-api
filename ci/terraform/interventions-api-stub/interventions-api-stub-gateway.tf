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

locals {
  orch_api_vpc_endpoint     = var.orchestration_vpc_endpoint_id != "" ? [var.orchestration_vpc_endpoint_id] : []
  new_auth_api_vpc_endpoint = var.new_auth_api_vpc_endpoint_id != "" ? [var.new_auth_api_vpc_endpoint_id] : []
  vpc_endpoint_ids          = concat(local.orch_api_vpc_endpoint, local.new_auth_api_vpc_endpoint, [data.aws_vpc_endpoint.auth_api_vpc_endpoint.id])
  vpc_environment           = var.vpc_environment == null ? var.environment : var.vpc_environment
}

resource "aws_api_gateway_rest_api" "interventions_api_stub" {
  name = "${var.environment}-di-interventions-api-stub"
  body = jsonencode({
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
  })

  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = local.vpc_endpoint_ids
  }
  lifecycle {
    create_before_destroy = true
  }
}

data "aws_iam_policy_document" "interventions_api_stub_policy" {
  statement {
    effect = "Allow"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = [
      "execute-api:Invoke"
    ]
    resources = [
      "${aws_api_gateway_rest_api.interventions_api_stub.execution_arn}/*"
    ]
  }

  statement {
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = [
      "execute-api:Invoke"
    ]
    resources = [
      "${aws_api_gateway_rest_api.interventions_api_stub.execution_arn}/*"
    ]
    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpce"
      values   = local.vpc_endpoint_ids
    }
  }
}

resource "aws_api_gateway_rest_api_policy" "interventions_api_stub_policy" {
  rest_api_id = aws_api_gateway_rest_api.interventions_api_stub.id
  policy      = data.aws_iam_policy_document.interventions_api_stub_policy.json
}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.account_interventions_stub_lambda.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = module.account_interventions_stub_lambda.endpoint_lambda_alias.name

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${aws_api_gateway_rest_api.interventions_api_stub.execution_arn}/*/*"
}


resource "aws_api_gateway_stage" "interventions_api_stub_stage" {
  deployment_id         = aws_api_gateway_deployment.interventions_api_stub_deployment.id
  rest_api_id           = aws_api_gateway_rest_api.interventions_api_stub.id
  stage_name            = var.environment
  cache_cluster_enabled = false
  xray_tracing_enabled  = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.interventions_api_stub_stage_access_logs.arn
    format          = local.access_logging_template
  }

  depends_on = [
    module.account_interventions_stub_role,
    aws_api_gateway_deployment.interventions_api_stub_deployment
  ]

  tags = {
    "FMSRegionalPolicy" = "false"
    "CustomPolicy"      = "apistub"
  }

}

resource "aws_api_gateway_deployment" "interventions_api_stub_deployment" {
  rest_api_id = aws_api_gateway_rest_api.interventions_api_stub.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_rest_api.interventions_api_stub.body,
      data.aws_iam_policy_document.interventions_api_stub_policy.json,
      local.vpc_endpoint_ids
    ]))
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.account_interventions_stub_lambda,
  ]
}

resource "aws_api_gateway_method_settings" "interventions_api_stub_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.interventions_api_stub.id
  stage_name  = aws_api_gateway_stage.interventions_api_stub_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = local.request_tracing_allowed
    logging_level      = "INFO"
    caching_enabled    = false
  }
  depends_on = [
    aws_api_gateway_stage.interventions_api_stub_stage
  ]
}

resource "aws_cloudwatch_log_group" "interventions_api_stub_stage_access_logs" {
  name              = "${var.environment}-auth-interventions-api-stub-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "interventions_api_stub_access_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-auth-interventions-api-stub-access-logs-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.interventions_api_stub_stage_access_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
