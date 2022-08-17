data "aws_dynamodb_table" "user_profile" {
  name = "${var.environment}-user-profile"
}

data "aws_dynamodb_table" "user_credential" {
  name = "${var.environment}-user-credentials"
}

data "aws_iam_policy_document" "verified_account_dynamo_access" {
  statement {
    sid    = "AllowAccessToUserProfileTable"
    effect = "Allow"

    actions = [
#      "dynamodb:Get*",
#      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:UpdateItem",
      "dynamodb:TransactWriteItem",
    ]

    resources = [
      data.aws_dynamodb_table.user_profile.arn,
    ]
  }

  statement {
    sid    = "AllowAccessToUserCredentialTable"
    effect = "Allow"

    actions = [
      "dynamodb:GetItem",
    ]

    resources = [
      data.aws_dynamodb_table.user_credential.arn,
    ]
  }
}

resource "aws_iam_policy" "verified_account_dynamo_full_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy for managing permissions to the Dynamo User Profile table"

  policy = data.aws_iam_policy_document.verified_account_dynamo_access.json
}

module "verified_account_update_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "verified_account_update_lambda_role"

  policies_to_attach = [
    aws_iam_policy.verified_account_dynamo_full_access.arn,
  ]
}

resource "aws_lambda_function" "verified_account_dynamo_update_lambda" {
  function_name = "${var.environment}-verified-account-dynamo-update-lambda"
  role          = module.verified_account_update_lambda_role.arn
  handler       = "uk.gov.di.authentication.utils.lambda.AccountVerifierLambda::handleRequest"
  timeout       = 900
  memory_size   = 4096
  runtime       = "java11"
  publish       = true

  s3_bucket         = aws_s3_object.utils_release_zip.bucket
  s3_key            = aws_s3_object.utils_release_zip.key
  s3_object_version = aws_s3_object.utils_release_zip.version_id

  environment {
    variables = merge({
      ENVIRONMENT = var.environment
    })
  }

  tags = local.default_tags
}


resource "aws_cloudwatch_log_group" "verified_account_update_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.verified_account_dynamo_update_lambda.function_name}"
  kms_key_id        = local.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  tags = local.default_tags
}

resource "aws_cloudwatch_log_subscription_filter" "verified_account_update_lambda_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "${aws_lambda_function.verified_account_dynamo_update_lambda.function_name}-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.verified_account_update_lambda_log_group[0].name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}