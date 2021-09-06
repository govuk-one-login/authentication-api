data "aws_iam_policy_document" "lambda_can_assume_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    principals {
      identifiers = [
        "lambda.amazonaws.com"
      ]
      type = "Service"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role" "lambda_iam_role" {
  name = "${var.environment}-account-management-standard-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json

  tags = local.default_tags
}

data "aws_iam_policy_document" "endpoint_logging_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:*:*:*",
    ]
  }
}

resource "aws_iam_policy" "endpoint_logging_policy" {
  name        = "${var.environment}-account-management-standard-lambda-logging"
  path        = "/"
  description = "IAM policy for logging from a Account Management API lambdas"

  policy = data.aws_iam_policy_document.endpoint_logging_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn
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
  name        = "${var.environment}-account-management-standard-lambda-xray"
  path        = "/"
  description = "IAM policy for xray with an account management lambda"

  policy = data.aws_iam_policy_document.endpoint_xray_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_xray_policy.arn
}

data "aws_iam_policy_document" "endpoint_networking_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeNetworkInterfaces",
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeInstances",
      "ec2:AttachNetworkInterface",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "sqs_lambda_iam_role" {
  name = "${var.environment}-account-management-sqs-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json
  tags = {
    environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "sqs_lambda_logs" {
  role       = aws_iam_role.sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn
}

resource "aws_iam_role_policy_attachment" "sqs_lambda_networking" {
  role       = aws_iam_role.sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn
}

resource "aws_iam_policy" "endpoint_networking_policy" {
  name        = "${var.environment}-account-management-standard-lambda-networking"
  path        = "/"
  description = "IAM policy for managing VPC connection for an account management lambda"

  policy = data.aws_iam_policy_document.endpoint_networking_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_networking" {
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn
}

data "aws_dynamodb_table" "user_credentials_table" {
  name = "${var.environment}-user-credentials"
}

data "aws_dynamodb_table" "user_profile_table" {
  name = "${var.environment}-user-profile"
}

data "aws_iam_policy_document" "dynamo_policy_document" {
  count = var.use_localstack ? 0 : 1
  statement {
    sid = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:GetItem",
      "dynamodb:UpdateItem",
      "dynamodb:DescribeTable",
    ]
    resources = [
      data.aws_dynamodb_table.user_credentials_table.arn,
      data.aws_dynamodb_table.user_profile_table.arn,
    ]
  }
}

resource "aws_iam_policy" "lambda_dynamo_policy" {
  count       = var.use_localstack ? 0 : 1
  name        = "${var.environment}-account-management-lambda-dynamo-policy"
  path        = "/"
  description = "IAM policy for managing Dynamo connection for an account management lambdas"

  policy = data.aws_iam_policy_document.dynamo_policy_document[0].json
}

resource "aws_iam_role_policy_attachment" "lambda_dynamo" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_dynamo_policy[0].arn
}
