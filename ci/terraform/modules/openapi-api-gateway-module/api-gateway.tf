resource "aws_api_gateway_rest_api" "api_gateway_rest_api" {
  name = "${var.environment}-${var.resource_prefix}"

  body = var.openapi_spec
  # body = templatefile(
  #   "${var.openapi_spec_file}",
  #   merge({
  #     environment = var.environment
  #   }, var.endpoint_modules)
  # )

  tags = var.default_tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  for_each = var.endpoint_modules

  statement_id  = "AllowInvokeFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = each.value.endpoint_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = each.value.endpoint_lambda_alias.name
  source_arn    = "${aws_api_gateway_rest_api.api_gateway_rest_api.execution_arn}/*/*"
}


resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.api_gateway_rest_api.id

  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.api_gateway_rest_api.body))
  }
}

resource "aws_api_gateway_stage" "stage" {
  deployment_id = aws_api_gateway_deployment.deployment.id
  rest_api_id   = aws_api_gateway_rest_api.api_gateway_rest_api.id
  stage_name    = var.environment

  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access_logs.arn
    format          = var.access_logging_template
  }

  tags = var.default_tags

  lifecycle {
    replace_triggered_by = [aws_api_gateway_deployment.deployment.id]
  }
}
data "aws_iam_policy_document" "api_gateway_can_assume_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    principals {
      identifiers = [
        "apigateway.amazonaws.com"
      ]
      type = "Service"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_api_gateway_base_path_mapping" "api" {
  api_id      = aws_api_gateway_rest_api.api_gateway_rest_api.id
  stage_name  = aws_api_gateway_stage.stage.stage_name
  domain_name = var.domain_name

  lifecycle {
    replace_triggered_by = [aws_api_gateway_stage.stage.id]
  }
}

module "dashboard" {
  source           = "../dashboards"
  api_gateway_name = aws_api_gateway_rest_api.api_gateway_rest_api.name
  use_localstack   = false
}
