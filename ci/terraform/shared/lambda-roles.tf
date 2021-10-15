module "standard_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "standard"
  vpc_arn     = aws_vpc.authentication.arn

  policies_to_attach = var.use_localstack ? [aws_iam_policy.endpoint_xray_policy.arn] : [
    aws_iam_policy.endpoint_xray_policy.arn,
    aws_iam_policy.lambda_kms_policy[0].arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy[0].arn,
    aws_iam_policy.lambda_dynamo_policy[0].arn
  ]
  default_tags = {
    environment = var.environment
  }
}

data "aws_iam_policy_document" "endpoint_xray_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    actions = [
      "xray:*"
    ]

    resources = [
      "*",
    ]
  }
}

resource "aws_iam_policy" "endpoint_xray_policy" {
  name        = "${var.environment}-standard-lambda-xray"
  path        = "/"
  description = "IAM policy for xray with a lambda"

  policy = data.aws_iam_policy_document.endpoint_xray_policy.json
}

module "sqs_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "sqs"
  vpc_arn     = aws_vpc.authentication.arn
  default_tags = {
    environment = var.environment
  }
}

module "dynamo_sqs_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "dynamo-sqs"
  vpc_arn     = aws_vpc.authentication.arn
  policies_to_attach = var.use_localstack ? [] : [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy[0].arn,
    aws_iam_policy.lambda_dynamo_policy[0].arn
  ]
  default_tags = {
    environment = var.environment
  }
}

module "token_lambda_role" {
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "token"
  vpc_arn     = aws_vpc.authentication.arn
  policies_to_attach = var.use_localstack ? [] : [
    aws_iam_policy.lambda_kms_policy[0].arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy[0].arn,
    aws_iam_policy.lambda_dynamo_policy[0].arn
  ]
  default_tags = {
    environment = var.environment
  }
}

module "email_notification_sqs_lambda_role" {
  source = "../modules/lambda-role"

  environment  = var.environment
  role_name    = "email-notification-sqs"
  vpc_arn      = aws_vpc.authentication.arn
  default_tags = local.default_tags
}
