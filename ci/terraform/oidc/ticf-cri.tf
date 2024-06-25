module "frontend_api_ticf_cri_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "frontend-api-ticf-cri-role"
  vpc_arn     = local.authentication_vpc_arn
  count       = local.deploy_ticf_cri_count
}

resource "aws_lambda_function" "ticf_cri_lambda" {
  count         = local.deploy_ticf_cri_count
  function_name = "${var.environment}-ticf-cri-lambda"
  role          = module.frontend_api_ticf_cri_role[0].arn
  handler       = "uk.gov.di.authentication.frontendapi.lambda.TicfCriHandler::handleRequest"
  runtime       = "java17"
  publish       = true

  memory_size                    = lookup(var.performance_tuning, "ticf-cri", local.default_performance_parameters).memory
  reserved_concurrent_executions = 1

  tracing_config {
    mode = "Active"
  }

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_object.frontend_api_release_zip.key
  s3_object_version = aws_s3_object.frontend_api_release_zip.version_id

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

  tags = local.default_tags
  # checkov:skip=CKV_AWS_116:Adding a DLQ would not be useful as we're not adding a retry policy.
}

resource "aws_cloudwatch_log_group" "ticf_cri_lambda_log_group" {
  count = local.deploy_ticf_cri_count # only create log group if lambda is deployed

  name              = "/aws/lambda/${aws_lambda_function.ticf_cri_lambda[0].function_name}"
  tags              = local.default_tags
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention
}

resource "aws_cloudwatch_log_subscription_filter" "ticf_cri_lambda_log_subscription" {
  count = local.deploy_ticf_cri_count == 1 ? length(var.logging_endpoint_arns) : 0 # only create log subscription(s) if lambda is deployed

  name            = "${aws_lambda_function.ticf_cri_lambda[0].function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.ticf_cri_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
