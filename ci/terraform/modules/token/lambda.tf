resource "aws_iam_role" "iam_for_token_lambda" {
  name = "iam_for_token_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_lambda_function" "token_lambda" {
  filename = var.lambda-zip-file
  function_name = "TokenLambda"
  role = aws_iam_role.iam_for_token_lambda.arn
  handler = "uk.gov.di.lambdas.TokenHandler::handleRequest"

  source_code_hash = filebase64sha256(var.lambda-zip-file)

  environment {
    variables = {
      BASE_URL = "http://some-base-url"
    }
  }

  runtime = "java11"
}

resource "aws_iam_policy" "token_lambda_logging" {
  name        = "token_lambda_logging"
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
  role       = aws_iam_role.iam_for_token_lambda.name
  policy_arn = aws_iam_policy.token_lambda_logging.arn
}