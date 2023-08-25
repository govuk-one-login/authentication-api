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

resource "aws_api_gateway_rest_api" "di_auth_ext_api" {
  name = "${var.environment}-di-auth-ext-api"

  tags   = local.default_tags
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "execute-api:Invoke",
            "Resource": [
                "execute-api:/*"
            ]
        },
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "execute-api:Invoke",
            "Resource": [
                "execute-api:/*"
            ],
            "Condition" : {
                "StringNotEquals": {
                    "aws:SourceVpce": "${data.aws_vpc_endpoint.auth_api_vpc_endpoint.id}"
                }
            }
        }
    ]
}
EOF
  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = [data.aws_vpc_endpoint.auth_api_vpc_endpoint.id]
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_usage_plan" "di_auth_ext_api_usage_plan" {
  name = "${var.environment}-di-auth-ext-api-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.di_auth_ext_api.id
    stage  = aws_api_gateway_stage.di_auth_ext_stage.stage_name
  }
  depends_on = [
    aws_api_gateway_stage.di_auth_ext_stage,
    aws_api_gateway_rest_api.di_auth_ext_api,
  ]
}

resource "aws_api_gateway_stage" "di_auth_ext_stage" {
  deployment_id         = aws_api_gateway_deployment.auth_ext_api_deployment.id
  rest_api_id           = aws_api_gateway_rest_api.di_auth_ext_api.id
  stage_name            = var.environment
  cache_cluster_enabled = false

  xray_tracing_enabled = true

  dynamic "access_log_settings" {
    for_each = var.use_localstack ? [] : aws_cloudwatch_log_group.oidc_stage_access_logs
    iterator = log_group
    content {
      destination_arn = log_group.value.arn
      format          = local.access_logging_template
    }
  }

  tags = local.default_tags
}

resource "aws_api_gateway_method_settings" "di_auth_ext_api_logging_settings" {
  count = var.enable_api_gateway_execution_logging ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.di_auth_ext_api.id
  stage_name  = aws_api_gateway_stage.di_auth_ext_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    data_trace_enabled = var.enable_api_gateway_execution_request_tracing && local.request_tracing_allowed
    logging_level      = "INFO"
    caching_enabled    = false
  }
  depends_on = [
    aws_api_gateway_stage.di_auth_ext_stage
  ]
}

resource "aws_api_gateway_deployment" "auth_ext_api_deployment" {
  rest_api_id = aws_api_gateway_rest_api.di_auth_ext_api.id

  lifecycle {
    create_before_destroy = true
  }
}

module "dashboard_auth_ext_api" {
  source           = "../modules/dashboards"
  api_gateway_name = aws_api_gateway_rest_api.di_auth_ext_api.name
  use_localstack   = false
}