data "aws_iam_policy_document" "account_metrics_dynamo_access" {
  statement {
    sid    = "AllowAccessToDescribeUserProfileTable"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
    ]

    resources = [
      data.aws_dynamodb_table.user_profile.arn,
    ]
  }

  statement {
    sid    = "AllowAccessToKms"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey",
    ]
    resources = [local.user_profile_kms_key_arn]
  }
}

data "aws_dynamodb_table" "user_profile" {
  name = "${var.environment}-user-profile"
}

resource "aws_iam_policy" "account_metrics_dynamo_access" {
  name_prefix = "account-metrics-dynamo-access-policy"
  description = "IAM policy for managing permissions to the Dynamo User Profile table"

  policy = data.aws_iam_policy_document.account_metrics_dynamo_access.json
}

module "account_metrics_update_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "account-metrics-lambda-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.account_metrics_dynamo_access.arn,
  ]
}

resource "aws_lambda_function" "account_metrics_lambda" {
  function_name = "${var.environment}-account-metrics-publish-lambda"
  role          = module.account_metrics_update_lambda_role.arn
  handler       = "uk.gov.di.authentication.utils.lambda.AccountMetricPublishHandler::handleRequest"
  timeout       = 900
  memory_size   = 4096
  runtime       = "java17"
  publish       = true

  s3_bucket         = aws_s3_object.utils_release_zip.bucket
  s3_key            = aws_s3_object.utils_release_zip.key
  s3_object_version = aws_s3_object.utils_release_zip.version_id

  vpc_config {
    security_group_ids = [local.allow_aws_service_access_security_group_id]
    subnet_ids         = local.authentication_private_subnet_ids

  }

  environment {
    variables = merge({
      ENVIRONMENT = var.environment
    })
  }
}

resource "aws_cloudwatch_log_group" "account_metrics_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.account_metrics_lambda.function_name}"
  kms_key_id        = local.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention
}


resource "aws_cloudwatch_log_subscription_filter" "account_metrics_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_lambda_function.account_metrics_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.account_metrics_lambda_log_group.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_cloudwatch_event_rule" "account_metrics_schedule" {
  name                = "${var.environment}-account-metrics-publish-schedule"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "account_metrics_schedule_target" {
  arn       = aws_lambda_function.account_metrics_lambda.arn
  rule      = aws_cloudwatch_event_rule.account_metrics_schedule.name
  target_id = aws_lambda_function.account_metrics_lambda.version
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_account_metrics_lambda" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.account_metrics_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.account_metrics_schedule.arn
}
