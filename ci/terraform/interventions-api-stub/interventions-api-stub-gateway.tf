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

resource "aws_api_gateway_rest_api" "interventions_api_stub" {
  name = "${var.environment}-di-interventions-api-stub"

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
    module.hello_world_role,
    aws_api_gateway_deployment.interventions_api_stub_deployment
  ]

  tags = local.default_tags
}

resource "aws_api_gateway_deployment" "interventions_api_stub_deployment" {
  rest_api_id = aws_api_gateway_rest_api.interventions_api_stub.id

  triggers = {
    redeployment = sha1(jsonencode([
      module.hello_world_lambda.integration_trigger_value,
      module.hello_world_lambda.method_trigger_value,
    ]))
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    module.hello_world_lambda,
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
