data "aws_iam_policy_document" "warmer_can_execute_endpoint_lambda" {
  statement {
    sid = "AllowExecutionFromWarmer"
    actions = [
      "lambda:InvokeFunction"
    ]
    resources = [
      aws_lambda_function.authorizer.arn
    ]
    effect = "Allow"
  }
}

resource "aws_iam_role" "lambda_warmer_role" {
  count = var.keep_lambdas_warm ? 1 : 0

  name               = "${aws_lambda_function.authorizer.function_name}-warmer-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json
}

resource "aws_iam_policy" "lambda_warmer_policy" {
  count = var.keep_lambdas_warm ? 1 : 0

  name        = "${aws_lambda_function.authorizer.function_name}-warmer-policy"
  policy      = data.aws_iam_policy_document.warmer_can_execute_endpoint_lambda.json
  description = "Allow warmer to invoke its related function"
}

resource "aws_iam_role_policy_attachment" "lambda_warmer_execution" {
  count = var.keep_lambdas_warm ? 1 : 0

  role       = aws_iam_role.lambda_warmer_role[0].name
  policy_arn = aws_iam_policy.lambda_warmer_policy[0].arn
}

data "aws_iam_policy_document" "lambda_logging_policy" {
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

resource "aws_iam_policy" "lambda_warmer_logging_policy" {
  count = var.keep_lambdas_warm ? 1 : 0

  name        = "${aws_lambda_function.authorizer.function_name}-warmer-policy-logging"
  path        = "/"
  description = "IAM policy for logging from a warmer lambda"

  policy = data.aws_iam_policy_document.lambda_logging_policy.json
}

resource "aws_iam_role_policy_attachment" "lambda_warmer_logs" {
  count = var.keep_lambdas_warm ? 1 : 0

  role       = aws_iam_role.lambda_warmer_role[0].name
  policy_arn = aws_iam_policy.lambda_warmer_logging_policy[0].arn
}

resource "aws_lambda_function" "warmer_function" {
  count = var.keep_lambdas_warm ? 1 : 0

  filename      = var.lambda_warmer_zip_file
  function_name = "${aws_lambda_function.authorizer.function_name}-lambda-warmer"
  role          = aws_iam_role.lambda_warmer_role[0].arn
  handler       = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
  timeout       = 60
  memory_size   = 1024

  tracing_config {
    mode = "Active"
  }

  source_code_hash = filebase64sha256(var.lambda_warmer_zip_file)

  environment {
    variables = {
      LAMBDA_ARN       = aws_lambda_function.authorizer.arn
      LAMBDA_QUALIFIER = aws_lambda_function.authorizer.version
      LAMBDA_TYPE      = "AUTHORIZER"
    }
  }

  runtime = "java11"

  tags = merge(local.default_tags, {
    lambda = "warmer"
  })
}

resource "aws_cloudwatch_log_group" "warmer_lambda_log_group" {
  count = var.keep_lambdas_warm ? 1 : 0

  name = "/aws/lambda/${aws_lambda_function.warmer_function[0].function_name}"
  tags = merge(local.default_tags, {
    lambda = "warmer"
  })
}

resource "aws_cloudwatch_event_rule" "warmer_schedule_rule" {
  count = var.keep_lambdas_warm ? 1 : 0

  name                = "${aws_lambda_function.warmer_function[0].function_name}-schedule"
  schedule_expression = "cron(0/5 * * * ? *)"
  is_enabled          = true
}

resource "aws_cloudwatch_event_target" "warmer_schedule_target" {
  count = var.keep_lambdas_warm ? 1 : 0

  arn  = aws_lambda_function.warmer_function[0].arn
  rule = aws_cloudwatch_event_rule.warmer_schedule_rule[0].name
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_warmer_lambda" {
  count = var.keep_lambdas_warm ? 1 : 0

  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.warmer_function[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.warmer_schedule_rule[0].arn
}