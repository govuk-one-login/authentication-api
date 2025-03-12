module "account_management_api_authorizer_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "account-management-api-authorizer-role"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    aws_iam_policy.lambda_kms_policy.arn,
    aws_iam_policy.dynamo_am_client_registry_read_access_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    local.client_registry_encryption_policy_arn
  ]
  extra_tags = {
    Service = "authorizer"
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

resource "aws_lambda_function" "authorizer" {
  function_name = "${var.environment}-api_gateway_authorizer"
  role          = module.account_management_api_authorizer_role.arn
  handler       = "uk.gov.di.accountmanagement.lambda.AuthoriseAccessTokenHandler::handleRequest"
  runtime       = "java17"

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_object.account_management_api_release_zip.key
  s3_object_version = aws_s3_object.account_management_api_release_zip.version_id

  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  publish     = true
  timeout     = 30
  memory_size = local.authorizer_memory_size

  vpc_config {
    security_group_ids = [local.allow_egress_security_group_id]
    subnet_ids         = local.private_subnet_ids
  }
  environment {
    variables = {
      TOKEN_SIGNING_KEY_ALIAS = data.aws_kms_key.id_token_public_key.key_id
      ENVIRONMENT             = var.environment
      JAVA_TOOL_OPTIONS       = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1 '--add-reads=jdk.jfr=ALL-UNNAMED'"
    }
  }
  kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn

  depends_on = [module.account_management_api_authorizer_role]
}

resource "aws_api_gateway_authorizer" "di_account_management_api" {
  name                             = "${var.environment}-authorise-access-token"
  rest_api_id                      = aws_api_gateway_rest_api.di_account_management_api.id
  authorizer_uri                   = aws_lambda_alias.authorizer_alias.invoke_arn
  authorizer_credentials           = aws_iam_role.invocation_role.arn
  authorizer_result_ttl_in_seconds = 0
}

resource "aws_lambda_alias" "authorizer_alias" {
  name             = "${var.environment}-authorizer-alias-lambda-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.authorizer.arn
  function_version = aws_lambda_function.authorizer.version
}

resource "aws_cloudwatch_log_group" "authorizer_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.authorizer.function_name}"
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.authorizer
  ]
}
moved {
  from = aws_cloudwatch_log_group.lambda_log_group
  to   = aws_cloudwatch_log_group.authorizer_lambda_log_group
}

resource "aws_cloudwatch_log_subscription_filter" "authorizer_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "authorizer-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.authorizer_lambda_log_group.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_lambda_provisioned_concurrency_config" "endpoint_lambda_concurrency_config" {
  count = local.authorizer_provisioned_concurrency == 0 ? 0 : 1

  function_name = aws_lambda_function.authorizer.function_name
  qualifier     = aws_lambda_alias.authorizer_alias.name

  provisioned_concurrent_executions = local.authorizer_provisioned_concurrency

  lifecycle {
    ignore_changes = [provisioned_concurrent_executions] # Ignoring as this is targeted by aws_app_autoscaling_target.lambda_target resource
  }

}

resource "aws_appautoscaling_target" "lambda_target" {
  count = local.authorizer_max_provisioned_concurrency > local.authorizer_provisioned_concurrency ? 1 : 0

  max_capacity       = local.authorizer_max_provisioned_concurrency
  min_capacity       = local.authorizer_provisioned_concurrency
  resource_id        = "function:${aws_lambda_function.authorizer.function_name}:${aws_lambda_alias.authorizer_alias.name}"
  scalable_dimension = "lambda:function:ProvisionedConcurrency"
  service_namespace  = "lambda"

  tags = {
    Service = "authorizer"
  }
}

resource "aws_appautoscaling_policy" "provisioned-concurrency-policy" {
  count = local.authorizer_max_provisioned_concurrency > local.authorizer_provisioned_concurrency ? 1 : 0

  name               = "LambdaProvisonedConcurrency:${aws_lambda_function.authorizer.function_name}"
  resource_id        = aws_appautoscaling_target.lambda_target[0].resource_id
  scalable_dimension = aws_appautoscaling_target.lambda_target[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.lambda_target[0].service_namespace
  policy_type        = "TargetTrackingScaling"

  target_tracking_scaling_policy_configuration {
    target_value = local.authorizer_scaling_trigger
    predefined_metric_specification {
      predefined_metric_type = "LambdaProvisionedConcurrencyUtilization"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "lambda_authorizer_error_metric_filter" {
  name           = replace("${var.environment}-${aws_lambda_function.authorizer.function_name}-errors", ".", "")
  pattern        = "{($.level = \"ERROR\")}"
  log_group_name = aws_cloudwatch_log_group.authorizer_lambda_log_group.name

  metric_transformation {
    name      = replace("${var.environment}-${aws_lambda_function.authorizer.function_name}-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_authorizer_error_cloudwatch_alarm" {
  alarm_name          = replace("${var.environment}-${aws_lambda_function.authorizer.function_name}-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.lambda_authorizer_error_metric_filter.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.lambda_authorizer_error_metric_filter.metric_transformation[0].namespace
  period              = "3600"
  statistic           = "Sum"
  threshold           = local.alert_error_threshold
  alarm_description   = "${local.alert_error_threshold} or more errors have occurred in the ${var.environment} ${aws_lambda_function.authorizer.function_name} lambda. ACCOUNT: ${local.aws_account_alias}"
  alarm_actions       = [local.slack_event_sns_topic_arn]

  tags = {
    Service = "authorizer"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_authorizer_error_rate_cloudwatch_alarm" {
  alarm_name          = replace("${var.environment}-${aws_lambda_function.authorizer.function_name}-error-rate-alarm", ".", "")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = local.alert_error_rate_threshold
  alarm_description   = "Lambda error rate of ${local.alert_error_rate_threshold} has been reached in the ${var.environment} ${aws_lambda_function.authorizer.function_name} lambda.ACCOUNT: ${local.aws_account_alias}"

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
        FunctionName = aws_lambda_function.authorizer.function_name
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
        FunctionName = aws_lambda_function.authorizer.function_name
      }
    }
  }
  alarm_actions = [local.slack_event_sns_topic_arn]

  tags = {
    Service = "authorizer"
  }
}
