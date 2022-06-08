resource "aws_lambda_function" "endpoint_lambda" {
  function_name = replace("${var.environment}-${var.endpoint_name}-lambda", ".", "")
  role          = var.lambda_role_arn
  handler       = var.handler_function_name
  timeout       = 30
  memory_size   = var.memory_size
  publish       = true

  tracing_config {
    mode = "Active"
  }

  s3_bucket         = var.source_bucket
  s3_key            = var.lambda_zip_file
  s3_object_version = var.lambda_zip_file_version

  code_signing_config_arn = var.code_signing_config_arn

  vpc_config {
    security_group_ids = var.security_group_ids
    subnet_ids         = var.subnet_id
  }
  environment {
    variables = merge(var.handler_environment_variables, {
      WARMER_DELAY      = var.warmer_delay_millis
      JAVA_TOOL_OPTIONS = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1"
    })
  }
  kms_key_arn = var.lambda_env_vars_encryption_kms_key_arn

  runtime = var.handler_runtime

  tags = var.default_tags
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.endpoint_lambda.function_name}"
  tags              = var.default_tags
  kms_key_id        = var.cloudwatch_key_arn
  retention_in_days = var.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.endpoint_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${var.endpoint_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_lambda_alias" "endpoint_lambda" {
  name             = replace("${var.environment}-${var.endpoint_name}-lambda-active", ".", "")
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.endpoint_lambda.arn
  function_version = aws_lambda_function.endpoint_lambda.version
}

resource "time_sleep" "wait_60_seconds" {
  depends_on = [aws_lambda_alias.endpoint_lambda]

  create_duration = "30s"
}

resource "aws_lambda_provisioned_concurrency_config" "endpoint_lambda_concurrency_config" {
  count = var.provisioned_concurrency == 0 ? 0 : 1

  function_name = aws_lambda_function.endpoint_lambda.function_name
  qualifier     = aws_lambda_alias.endpoint_lambda.name

  provisioned_concurrent_executions = var.provisioned_concurrency
}

resource "aws_appautoscaling_target" "lambda_target" {
  count = var.max_provisioned_concurrency > var.provisioned_concurrency ? 1 : 0

  max_capacity       = var.max_provisioned_concurrency
  min_capacity       = var.provisioned_concurrency
  resource_id        = "function:${aws_lambda_function.endpoint_lambda.function_name}:${aws_lambda_alias.endpoint_lambda.name}"
  scalable_dimension = "lambda:function:ProvisionedConcurrency"
  service_namespace  = "lambda"
}

resource "aws_appautoscaling_policy" "provisioned-concurrency-policy" {
  count = var.max_provisioned_concurrency > var.provisioned_concurrency ? 1 : 0

  name               = "LambdaProvisonedConcurrency:${aws_lambda_function.endpoint_lambda.function_name}"
  resource_id        = aws_appautoscaling_target.lambda_target[0].resource_id
  scalable_dimension = aws_appautoscaling_target.lambda_target[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.lambda_target[0].service_namespace
  policy_type        = "TargetTrackingScaling"

  target_tracking_scaling_policy_configuration {
    target_value = var.scaling_trigger
    predefined_metric_specification {
      predefined_metric_type = "LambdaProvisionedConcurrencyUtilization"
    }
  }
}
