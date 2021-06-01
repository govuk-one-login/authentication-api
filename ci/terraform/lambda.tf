resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

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

resource "aws_lambda_function" "userinfo_lambda" {
  filename = var.lambda-zip-file
  function_name = "UserInfoLambda"
  role = aws_iam_role.iam_for_lambda.arn
  handler = "uk.gov.di.userinfo.UserInfoHandler::handleRequest"

  source_code_hash = filebase64sha256(var.lambda-zip-file)

  runtime = "java11"
}