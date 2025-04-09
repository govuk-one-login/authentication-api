data "aws_iam_policy_document" "mfa_method_analysis_dynamo_access" {
  statement {
    sid    = "AllowAccessToFetchUserTablesData"
    effect = "Allow"

    actions = [
      "dynamodb:Scan",
      "dynamodb:BatchGetItem",
    ]

    resources = [
      data.aws_dynamodb_table.user_profile.arn,
      "${data.aws_dynamodb_table.user_profile.arn}/index/PhoneNumberIndex",
      data.aws_dynamodb_table.user_credentials.arn,
    ]
  }
  statement {
    sid    = "AllowAccessToKms"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [local.user_profile_kms_key_arn, local.user_credentials_kms_key_arn]
  }
}

resource "aws_iam_policy" "mfa_method_analysis_dynamo_access" {
  name_prefix = "account-metrics-dynamo-access-policy"
  description = "IAM policy for managing permissions to for the MFA method analysis lambda"

  policy = data.aws_iam_policy_document.mfa_method_analysis_dynamo_access.json
}

module "mfa_method_analysis_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "mfa-method-analysis-lambda-role"

  policies_to_attach = [
    aws_iam_policy.mfa_method_analysis_dynamo_access.arn,
  ]
}

resource "aws_lambda_function" "mfa_method_analysis_lambda" {
  function_name = "${var.environment}-mfa-method-analysis-lambda"
  role          = module.mfa_method_analysis_lambda_role.arn
  handler       = "uk.gov.di.authentication.utils.lambda.MFAMethodAnalysisHandler::handleRequest"
  timeout       = 900
  memory_size   = 4096
  runtime       = "java17"
  publish       = true

  s3_bucket         = aws_s3_object.utils_release_zip.bucket
  s3_key            = aws_s3_object.utils_release_zip.key
  s3_object_version = aws_s3_object.utils_release_zip.version_id

  environment {
    variables = merge({
      ENVIRONMENT = var.environment
    })
  }
}

resource "aws_cloudwatch_log_group" "mfa_method_analysis_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.mfa_method_analysis_lambda.function_name}"
  kms_key_id        = local.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention
}


resource "aws_cloudwatch_log_subscription_filter" "mfa_method_analysis_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_lambda_function.mfa_method_analysis_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.mfa_method_analysis_lambda_log_group.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}
