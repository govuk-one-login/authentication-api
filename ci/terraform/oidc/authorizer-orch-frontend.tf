module "orch_frontend_authorizer_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "orch-fe-authorizer-role"
  vpc_arn     = local.authentication_vpc_arn
  extra_tags = {
    Service = "orch-frontend-authorizer"
  }
}

locals {
  authorizer_memory_size                 = lookup(var.performance_tuning, "authorizer", local.default_performance_parameters).memory
  authorizer_provisioned_concurrency     = lookup(var.performance_tuning, "authorizer", local.default_performance_parameters).concurrency
  authorizer_max_provisioned_concurrency = lookup(var.performance_tuning, "authorizer", local.default_performance_parameters).max_concurrency
  authorizer_scaling_trigger             = lookup(var.performance_tuning, "authorizer", local.default_performance_parameters).scaling_trigger

  alert_error_threshold      = 5
  alert_error_rate_threshold = 10
}

resource "aws_lambda_function" "orch_frontend_authorizer" {
  function_name = "${var.environment}-orch-fe-authorizer-lambda"
  role          = module.orch_frontend_authorizer_role.arn
  handler       = "uk.gov.di.authentication.oidc.lambda.OrchFrontendAuthorizerHandler::handleRequest"
  runtime       = "java17"

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_object.oidc_api_release_zip.key
  s3_object_version = aws_s3_object.oidc_api_release_zip.version_id

  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  publish     = true
  timeout     = 30
  memory_size = local.authorizer_memory_size

  vpc_config {
    security_group_ids = [local.authentication_egress_security_group_id]
    subnet_ids         = local.authentication_private_subnet_ids
  }
  environment {
    variables = {
      ENVIRONMENT       = var.environment
      JAVA_TOOL_OPTIONS = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1 '--add-reads=jdk.jfr=ALL-UNNAMED'"
    }
  }
  kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  tags = {
    Service = "orch-frontend-authorizer"
  }
}

resource "aws_iam_role" "orch_frontend_authorizer_invocation_role" {
  name = "${var.environment}-orch-fe-authorizer-invocation"
  path = "/"

  assume_role_policy = data.aws_iam_policy_document.api_gateway_can_assume_policy.json
  tags = {
    Service = "orch-frontend-authorizer"
  }
}


resource "aws_iam_role_policy" "invocation_policy" {
  name = "default"
  role = aws_iam_role.orch_frontend_authorizer_invocation_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "lambda:InvokeFunction",
      "Effect": "Allow",
      "Resource": [
          "${aws_lambda_alias.orch_frontend_authorizer_alias.arn}"
        ]
    }
  ]
}
EOF
}

resource "aws_api_gateway_authorizer" "orch_frontend_authorizer" {
  name                             = "${var.environment}-orch-fe-authorizer"
  rest_api_id                      = aws_api_gateway_rest_api.di_authentication_api.id
  authorizer_uri                   = aws_lambda_alias.orch_frontend_authorizer_alias.invoke_arn
  authorizer_credentials           = aws_iam_role.orch_frontend_authorizer_invocation_role.arn
  authorizer_result_ttl_in_seconds = var.environment == "integration" || var.environment == "production" ? 3600 : 60
  type                             = "REQUEST"
  identity_source                  = var.environment == "integration" || var.environment == "production" ? "context.identity.apiId" : "context.identity.sourceIp"
}

resource "aws_lambda_alias" "orch_frontend_authorizer_alias" {
  name             = "${var.environment}-orch-fe-authorizer-alias-lambda-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.orch_frontend_authorizer.arn
  function_version = aws_lambda_function.orch_frontend_authorizer.version
}


resource "aws_lambda_provisioned_concurrency_config" "orch_frontend_authorizer_concurrency_config" {
  count = local.authorizer_provisioned_concurrency == 0 ? 0 : 1

  function_name = aws_lambda_function.orch_frontend_authorizer.function_name
  qualifier     = aws_lambda_alias.orch_frontend_authorizer_alias.name

  provisioned_concurrent_executions = local.authorizer_provisioned_concurrency
}

resource "aws_appautoscaling_target" "orch_frontend_authorizer_lambda_target" {
  count = local.authorizer_max_provisioned_concurrency > local.authorizer_provisioned_concurrency ? 1 : 0

  max_capacity       = local.authorizer_max_provisioned_concurrency
  min_capacity       = local.authorizer_provisioned_concurrency
  resource_id        = "function:${aws_lambda_function.orch_frontend_authorizer.function_name}:${aws_lambda_alias.orch_frontend_authorizer_alias.name}"
  scalable_dimension = "lambda:function:ProvisionedConcurrency"
  service_namespace  = "lambda"
  tags = {
    Service = "orch-frontend-authorizer"
  }
}

resource "aws_appautoscaling_policy" "orch_frontend_authorizer_concurrency_policy" {
  count = local.authorizer_max_provisioned_concurrency > local.authorizer_provisioned_concurrency ? 1 : 0

  name               = "LambdaProvisonedConcurrency:${aws_lambda_function.orch_frontend_authorizer.function_name}"
  resource_id        = aws_appautoscaling_target.orch_frontend_authorizer_lambda_target[0].resource_id
  scalable_dimension = aws_appautoscaling_target.orch_frontend_authorizer_lambda_target[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.orch_frontend_authorizer_lambda_target[0].service_namespace
  policy_type        = "TargetTrackingScaling"

  target_tracking_scaling_policy_configuration {
    target_value = local.authorizer_scaling_trigger
    predefined_metric_specification {
      predefined_metric_type = "LambdaProvisionedConcurrencyUtilization"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "lambda_authorizer_error_metric_filter" {
  name           = replace("${var.environment}-${aws_lambda_function.orch_frontend_authorizer.function_name}-errors", ".", "")
  pattern        = "{($.level = \"ERROR\")}"
  log_group_name = aws_cloudwatch_log_group.orch_frontend_authorizer_logs.name

  metric_transformation {
    name      = replace("${var.environment}-${aws_lambda_function.orch_frontend_authorizer.function_name}-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_authorizer_error_cloudwatch_alarm" {
  alarm_name          = replace("${var.environment}-${aws_lambda_function.orch_frontend_authorizer.function_name}-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.lambda_authorizer_error_metric_filter.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.lambda_authorizer_error_metric_filter.metric_transformation[0].namespace
  period              = "3600"
  statistic           = "Sum"
  threshold           = local.alert_error_threshold
  alarm_description   = "${local.alert_error_threshold} or more errors have occurred in the ${var.environment} ${aws_lambda_function.orch_frontend_authorizer.function_name} lambda. ACCOUNT: ${local.aws_account_alias}"
  alarm_actions       = [local.slack_event_sns_topic_arn]
  tags = {
    Service = "orch-frontend-authorizer"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_authorizer_error_rate_cloudwatch_alarm" {
  alarm_name          = replace("${var.environment}-${aws_lambda_function.orch_frontend_authorizer.function_name}-error-rate-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = local.alert_error_rate_threshold
  alarm_description   = "Lambda error rate of ${local.alert_error_rate_threshold} has been reached in the ${var.environment} ${aws_lambda_function.orch_frontend_authorizer.function_name} lambda.ACCOUNT: ${local.aws_account_alias}"

  metric_query {
    id          = "e1"
    return_data = true
    expression  = "m2/m1*100"
    label       = "Error Rate"
  }

  metric_query {
    id = "m1"
    metric {
      namespace   = "AWS/Lambda"
      metric_name = "Invocations"
      period      = 60
      stat        = "Sum"
      unit        = "Count"

      dimensions = {
        FunctionName = aws_lambda_function.orch_frontend_authorizer.function_name
      }
    }
  }
  metric_query {
    id = "m2"
    metric {
      namespace   = "AWS/Lambda"
      metric_name = "Errors"
      period      = 60
      stat        = "Sum"
      unit        = "Count"

      dimensions = {
        FunctionName = aws_lambda_function.orch_frontend_authorizer.function_name
      }
    }
  }
  alarm_actions = [local.slack_event_sns_topic_arn]
  tags = {
    Service = "orch-frontend-authorizer"
  }
}
