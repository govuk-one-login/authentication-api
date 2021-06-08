resource "aws_iam_role" "lambda_iam_role" {
  name = "${var.endpoint_name}-${var.environment}-lambda-role"

  assume_role_policy = var.lambda_iam_policy
}

resource "aws_lambda_function" "endpoint_lambda" {
  filename      = var.lambda_zip_file
  function_name = replace("${var.endpoint_name}-${var.environment}-lambda", ".", "")
  role          = aws_iam_role.lambda_iam_role.arn
  handler       = var.handler_function_name

  source_code_hash = filebase64sha256(var.lambda_zip_file)
  vpc_config {
    security_group_ids = [var.security_group_id]
    subnet_ids = []
  }
  environment {
    variables = var.handler_environment_variables
  }

  runtime = var.handler_runtime
}

resource "aws_iam_policy" "endpoint_logging_policy" {
  name        = "${var.endpoint_name}_lambda_logging"
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