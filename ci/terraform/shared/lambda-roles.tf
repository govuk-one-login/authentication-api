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
  name = "${var.environment}-standard-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json
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
  name        = "${var.environment}-standard-lambda-logging"
  path        = "/"
  description = "IAM policy for logging from a lambda"

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
  name        = "${var.environment}-standard-lambda-xray"
  path        = "/"
  description = "IAM policy for xray with a lambda"

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
    ]
    resources = ["*"]
    condition {
      test     = "ArnLikeIfExists"
      variable = "ec2:Vpc"
      values   = [local.vpc_arn]
    }
  }
}

resource "aws_iam_policy" "endpoint_networking_policy" {
  name        = "${var.environment}-standard-lambda-networking"
  path        = "/"
  description = "IAM policy for managing VPC connection for a lambda"

  policy = data.aws_iam_policy_document.endpoint_networking_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_networking" {
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn
}

resource "aws_iam_role" "sqs_lambda_iam_role" {
  name = "${var.environment}-sqs-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json
}

resource "aws_iam_role_policy_attachment" "sqs_lambda_logs" {
  role       = aws_iam_role.sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn
}

resource "aws_iam_role_policy_attachment" "sqs_lambda_networking" {
  role       = aws_iam_role.sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn
}

resource "aws_iam_role" "dynamo_sqs_lambda_iam_role" {
  name = "${var.environment}-dynamo-sqs-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json
}

resource "aws_iam_role_policy_attachment" "dynamo_sqs_lambda_logs" {
  role       = aws_iam_role.dynamo_sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn
}

resource "aws_iam_role_policy_attachment" "dynamo_sqs_lambda_networking" {
  role       = aws_iam_role.dynamo_sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn
}

resource "aws_iam_role" "token_lambda_iam_role" {
  name               = "${var.environment}-token-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json
}

resource "aws_iam_role_policy_attachment" "token_lambda_logs" {
  role       = aws_iam_role.token_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn
}

resource "aws_iam_role_policy_attachment" "token_lambda_networking" {
  role       = aws_iam_role.token_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn
}

resource "aws_iam_role" "email_lambda_iam_role" {
  name = "${var.environment}-email-notification-sqs-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json
}

resource "aws_iam_role_policy_attachment" "emaiL_lambda_logging_policy" {
  role       = aws_iam_role.email_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn

  depends_on = [
    aws_iam_role.email_lambda_iam_role,
    aws_iam_policy.endpoint_logging_policy,
  ]
}

resource "aws_iam_role_policy_attachment" "email_lambda_networking_policy" {
  role       = aws_iam_role.email_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn

  depends_on = [
    aws_iam_role.email_lambda_iam_role,
    aws_iam_policy.endpoint_networking_policy,
  ]
}
