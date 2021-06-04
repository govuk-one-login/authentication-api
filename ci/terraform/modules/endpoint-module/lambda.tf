resource "aws_iam_role" "lambda_iam_role" {
  name = "${var.endpoint-name}-${var.environment}-lambda-role"

  assume_role_policy = var.lambda-iam-policy
}

resource "aws_lambda_function" "authorize_lambda" {
  filename      = var.lambda-zip-file
  function_name = "${var.endpoint-name}-${var.environment}-lambda"
  role          = aws_iam_role.lambda_iam_role.arn
  handler       = var.handler-function-name

  source_code_hash = filebase64sha256(var.lambda-zip-file)

  environment {
    variables = var.handler-environment-variables
  }

  runtime = var.handler-runtime
}

resource "aws_iam_policy" "endpoint_logging_policy" {
  name        = "${var.endpoint-name}_lambda_logging"
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