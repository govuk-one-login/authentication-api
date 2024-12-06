module "frontend_api_ticf_cri_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "frontend-api-ticf-cri-role"
  vpc_arn     = local.authentication_vpc_arn
  count       = local.deploy_ticf_cri_count
  extra_tags = {
    Service = "ticf-cri"
  }
}

locals {
  # All the tuning parameters in here specifically point to any overrides for account interventions
  # This is deliberate - for now we want to scale up this lambda in tandem with account interventions, since
  # they are called in roughly the same number of places
  provisioned_concurrency = lookup(var.performance_tuning, "account-interventions", local.default_performance_parameters).concurrency
}

resource "aws_lambda_function" "ticf_cri_lambda" {
  count         = local.deploy_ticf_cri_count
  function_name = "${var.environment}-ticf-cri-lambda"
  role          = module.frontend_api_ticf_cri_role[count.index].arn
  handler       = "uk.gov.di.authentication.frontendapi.lambda.TicfCriHandler::handleRequest"
  runtime       = "java17"
  publish       = true
  timeout       = 60

  reserved_concurrent_executions = 1

  tracing_config {
    mode = "Active"
  }

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_object.frontend_api_release_zip.key
  s3_object_version = aws_s3_object.frontend_api_release_zip.version_id

  memory_size = lookup(var.performance_tuning, "account-interventions", local.default_performance_parameters).memory

  kms_key_arn             = local.lambda_env_vars_encryption_kms_key_arn
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  vpc_config {
    security_group_ids = [local.authentication_egress_security_group_id]
    subnet_ids         = local.authentication_private_subnet_ids
  }

  environment {
    variables = merge(var.notify_template_map, {
      ENVIRONMENT                   = var.environment
      TICF_CRI_SERVICE_CALL_TIMEOUT = var.ticf_cri_service_call_timeout
      TICF_CRI_SERVICE_URI          = var.ticf_cri_service_uri
    })
  }
  # checkov:skip=CKV_AWS_116:Adding a DLQ would not be useful as we're not adding a retry policy.
  tags = {
    Service = "ticf-cri"
  }
}

resource "aws_lambda_provisioned_concurrency_config" "ticf_lambda_concurrency_config" {
  count = local.deploy_ticf_cri_count == 0 || local.provisioned_concurrency == 0 ? 0 : 1

  function_name = aws_lambda_function.ticf_cri_lambda[0].function_name
  qualifier     = aws_lambda_alias.ticf_cri_lambda_alias[0].name

  provisioned_concurrent_executions = local.provisioned_concurrency

  lifecycle {
    ignore_changes = [provisioned_concurrent_executions]
  }
}

resource "aws_appautoscaling_target" "ticf_lambda_target" {
  count = local.deploy_ticf_cri_count

  max_capacity       = lookup(var.performance_tuning, "account-interventions", local.default_performance_parameters).max_concurrency
  min_capacity       = lookup(var.performance_tuning, "account-interventions", local.default_performance_parameters).concurrency
  resource_id        = "function:${aws_lambda_function.ticf_cri_lambda[0].function_name}:${aws_lambda_alias.ticf_cri_lambda_alias[0].name}"
  scalable_dimension = "lambda:function:ProvisionedConcurrency"
  service_namespace  = "lambda"
}

resource "aws_appautoscaling_policy" "ticf_provisioned_concurrency_policy" {
  count = local.deploy_ticf_cri_count

  name               = "LambdaProvisonedConcurrency:${aws_lambda_function.ticf_cri_lambda[0].function_name}"
  resource_id        = aws_appautoscaling_target.ticf_lambda_target[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ticf_lambda_target[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ticf_lambda_target[0].service_namespace
  policy_type        = "TargetTrackingScaling"

  target_tracking_scaling_policy_configuration {
    target_value = lookup(var.performance_tuning, "account-interventions", local.default_performance_parameters).scaling_trigger
    predefined_metric_specification {
      predefined_metric_type = "LambdaProvisionedConcurrencyUtilization"
    }
  }
}

resource "aws_cloudwatch_log_group" "ticf_cri_lambda_log_group" {
  count = local.deploy_ticf_cri_count # only create log group if lambda is deployed

  name              = "/aws/lambda/${aws_lambda_function.ticf_cri_lambda[count.index].function_name}"
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention
  tags = {
    Service = "ticf-cri"
  }
}

resource "aws_cloudwatch_log_subscription_filter" "ticf_cri_lambda_log_subscription" {
  count = local.deploy_ticf_cri_count == 1 ? length(var.logging_endpoint_arns) : 0 # only create log subscription(s) if lambda is deployed

  name            = "${aws_lambda_function.ticf_cri_lambda[count.index].function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.ticf_cri_lambda_log_group[count.index].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_iam_policy" "ticf_cri_lambda_invocation_policy" {
  count       = local.deploy_ticf_cri_count
  name_prefix = "ticf-cri-lambda-invocation-policy"
  description = "IAM policy managing lambda invocation access for the TICF CRI lambda."

  policy = data.aws_iam_policy_document.ticf_cri_lambda_invocation_policy_document[count.index].json
  tags = {
    Service = "ticf-cri"
  }
}

resource "aws_lambda_alias" "ticf_cri_lambda_alias" {
  count            = local.deploy_ticf_cri_count
  name             = "${var.environment}-ticf-cri-lambda-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.ticf_cri_lambda[0].arn
  function_version = aws_lambda_function.ticf_cri_lambda[0].version
}

data "aws_iam_policy_document" "ticf_cri_lambda_invocation_policy_document" {
  count = local.deploy_ticf_cri_count
  statement {
    sid    = "AllowLambdaInvocation"
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction",
    ]

    resources = [
      aws_lambda_alias.ticf_cri_lambda_alias[0].arn,
    ]
  }
}
