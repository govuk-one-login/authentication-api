data "aws_iam_policy_document" "authorize_can_execute_authorize_request_uri_lambda" {
  statement {
    sid = "AllowExecutionFromWarmer"
    actions = [
      "lambda:InvokeFunction"
    ]
    resources = [
      aws_lambda_function.authorize_request_uri_lambda.arn
    ]
    effect = "Allow"
  }
}

resource "aws_iam_policy" "authorize_invoke_lambda_policy" {
  name_prefix = "authorize-invoke-lambda-policy"
  path        = "/${var.environment}/oidc-default/"
  policy      = data.aws_iam_policy_document.authorize_can_execute_authorize_request_uri_lambda.json

  description = "Allow authorize to invoke the authroize request uri lambda"
}