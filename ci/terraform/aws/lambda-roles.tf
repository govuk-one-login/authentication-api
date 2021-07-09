resource "aws_iam_role" "lambda_iam_role" {
  name = "${var.environment}-standard-lambda-role"

  assume_role_policy = var.lambda_iam_policy
  tags = {
    environment = var.environment
  }
}

resource "aws_iam_policy" "endpoint_logging_policy" {
  name        = "${var.environment}-standard-lambda-logging"
  path        = "/"
  description = "IAM policy for logging from a lambda"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:CreateLogGroup"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn
}

resource "aws_iam_policy" "endpoint_networking_policy" {
  name        = "${var.environment}-standard-lambda-networking"
  path        = "/"
  description = "IAM policy for managing VPC connection for a lambda"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeNetworkInterfaces",
        "ec2:CreateNetworkInterface",
        "ec2:DeleteNetworkInterface",
        "ec2:DescribeInstances",
        "ec2:AttachNetworkInterface"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_networking" {
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn
}

resource "aws_iam_role" "sqs_lambda_iam_role" {
  name = "${var.environment}-sqs-lambda-role"

  assume_role_policy = var.lambda_iam_policy
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

resource "aws_iam_role" "dynamo_sqs_lambda_iam_role" {
  name = "${var.environment}-dynamo-sqs-lambda-role"

  assume_role_policy = var.lambda_iam_policy
  tags = {
    environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "dynamo_sqs_lambda_logs" {
  role       = aws_iam_role.dynamo_sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn
}

resource "aws_iam_role_policy_attachment" "dynamo_sqs_lambda_networking" {
  role       = aws_iam_role.dynamo_sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn
}