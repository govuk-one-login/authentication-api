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


resource "aws_api_gateway_rest_api" "ticf_cri_stub" {
  name = "${var.environment}-di-ticf-cri-stub"
  body = jsonencode({
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

  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = [data.aws_vpc_endpoint.auth_api_vpc_endpoint.id]
  }
  lifecycle {
    create_before_destroy = true
  }
}

data "aws_iam_policy_document" "ticf_cri_stub_policy" {
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
      "${aws_api_gateway_rest_api.ticf_cri_stub.execution_arn}/*"
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
      "${aws_api_gateway_rest_api.ticf_cri_stub.execution_arn}/*"
    ]
    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpce"
      values = [
        data.aws_vpc_endpoint.auth_api_vpc_endpoint.id
      ]
    }
  }
}

resource "aws_api_gateway_rest_api_policy" "ticf_cri_stub_policy" {
  rest_api_id = aws_api_gateway_rest_api.ticf_cri_stub.id
  policy      = data.aws_iam_policy_document.ticf_cri_stub_policy.json
}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.ticf_cri_stub_lambda.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = module.ticf_cri_stub_lambda.endpoint_lambda_alias.name

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${aws_api_gateway_rest_api.ticf_cri_stub.execution_arn}/*/*"
}


resource "aws_api_gateway_stage" "ticf_cri_stub_stage" {
  deployment_id         = aws_api_gateway_deployment.ticf_cri_stub_deployment.id
  rest_api_id           = aws_api_gateway_rest_api.ticf_cri_stub.id
  stage_name            = var.environment
  cache_cluster_enabled = false
  xray_tracing_enabled  = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.ticf_cri_stub_stage_access_logs.arn
    format          = local.access_logging_template
  }

  depends_on = [
    module.ticf_cri_stub_role,
    aws_api_gateway_deployment.ticf_cri_stub_deployment
  ]
}

resource "aws_api_gateway_deployment" "ticf_cri_stub_deployment" {
  rest_api_id = aws_api_gateway_rest_api.ticf_cri_stub.id

  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.ticf_cri_stub.body))
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.ticf_cri_stub_lambda,
  ]
}

resource "aws_api_gateway_method_settings" "ticf_cri_stub_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.ticf_cri_stub.id
  stage_name  = aws_api_gateway_stage.ticf_cri_stub_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = local.request_tracing_allowed
    logging_level      = "INFO"
    caching_enabled    = false
  }
  depends_on = [
    aws_api_gateway_stage.ticf_cri_stub_stage
  ]
}

resource "aws_cloudwatch_log_group" "ticf_cri_stub_stage_access_logs" {
  name              = "${var.environment}-auth-ticf-cri-stub-access-logs"
  retention_in_days = var.cloudwatch_log_retention
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
}

resource "aws_cloudwatch_log_subscription_filter" "ticf_cri_stub_access_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.environment}-auth-ticf-cri-stub-access-logs-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.ticf_cri_stub_stage_access_logs.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
