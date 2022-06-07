module "ipv_spot_response_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "ipv-spot-response-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.dynamo_identity_credentials_write_access_policy.arn,
    aws_iam_policy.dynamo_identity_credentials_read_access_policy.arn,
    aws_iam_policy.dynamo_identity_credentials_delete_access_policy.arn,
    aws_iam_policy.spot_response_sqs_read_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.lambda_sns_policy.arn,
  ]

  depends_on = [
    aws_iam_policy.spot_response_sqs_read_policy
  ]
}

data "aws_iam_policy_document" "spot_response_policy_document" {
  statement {
    sid    = "ReceiveSQS"
    effect = "Allow"

    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ChangeMessageVisibility",
    ]

    resources = [
      aws_ssm_parameter.spot_response_queue_arn.value
    ]
  }
  statement {
    sid    = "AccessKMS"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
    ]

    resources = [
      aws_ssm_parameter.spot_response_queue_kms_arn.value
    ]
  }

  depends_on = [
    time_sleep.wait_60_seconds
  ]
}

resource "aws_iam_policy" "spot_response_sqs_read_policy" {
  policy      = data.aws_iam_policy_document.spot_response_policy_document.json
  path        = "/${var.environment}/sqs/"
  name_prefix = "spot-response-sqs-read-policy-policy"
}

resource "aws_lambda_event_source_mapping" "spot_response_lambda_sqs_mapping" {
  count            = var.spot_enabled ? 1 : 0
  event_source_arn = aws_ssm_parameter.spot_response_queue_arn.value
  function_name    = aws_lambda_function.spot_response_lambda.arn

  depends_on = [
    aws_lambda_function.spot_response_lambda,
    aws_iam_policy.spot_response_sqs_read_policy
  ]
}

resource "aws_lambda_function" "spot_response_lambda" {
  function_name = "${var.environment}-spot-response-lambda"
  role          = module.ipv_spot_response_role.arn
  handler       = "uk.gov.di.authentication.ipv.lambda.SPOTResponseHandler::handleRequest"
  timeout       = 30
  memory_size   = 512
  runtime       = "java11"
  publish       = true

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_bucket_object.ipv_api_release_zip.key
  s3_object_version = aws_s3_bucket_object.ipv_api_release_zip.version_id

  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  vpc_config {
    security_group_ids = [local.authentication_egress_security_group_id]
    subnet_ids         = local.authentication_subnet_ids
  }
  environment {
    variables = merge({
      AUDIT_SIGNING_KEY_ALIAS = local.audit_signing_key_alias_name
      DYNAMO_ENDPOINT         = var.use_localstack ? var.lambda_dynamo_endpoint : null
      ENVIRONMENT             = var.environment
      EVENTS_SNS_TOPIC_ARN    = aws_sns_topic.events.arn
      FRONTEND_BASE_URL       = module.dns.frontend_url
    })
  }
  kms_key_arn = local.lambda_env_vars_encryption_kms_key_arn

  tags = local.default_tags
}

resource "aws_cloudwatch_log_group" "spot_response_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.spot_response_lambda.function_name}"
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  tags = local.default_tags

  depends_on = [
    aws_lambda_function.spot_response_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "spot_response_lambda_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_lambda_function.spot_response_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.spot_response_lambda_log_group.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_lambda_alias" "spot_response_lambda_active" {
  name             = "${aws_lambda_function.spot_response_lambda.function_name}-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.spot_response_lambda.arn
  function_version = aws_lambda_function.spot_response_lambda.version
}