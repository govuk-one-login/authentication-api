resource "aws_lambda_function" "warmer_function" {
  count = var.warmer_handler_function_name == null ? 0 : 1

  filename      = var.warmer_lambda_zip_file
  function_name = replace("${var.environment}-${var.endpoint_name}-lambda-warmer", ".", "")
  role          = var.warmer_lambda_role_arn
  handler       = var.warmer_handler_function_name
  timeout       = 60
  memory_size   = 4096

  tracing_config {
    mode = "Active"
  }

  source_code_hash = filebase64sha256(var.warmer_lambda_zip_file)

  environment {
    variables = var.warmer_handler_environment_variables
  }

  runtime = var.warmer_handler_runtime

  tags = merge(var.default_tags, {
    lambda = "warmer"
  })
}

resource "aws_cloudwatch_log_group" "warmer_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name  = "/aws/lambda/${aws_lambda_function.warmer_function[0].function_name}"
  tags = merge(var.default_tags, {
    lambda = "warmer"
  })
}

resource "aws_cloudwatch_event_rule" "warmer_schedule_rule" {
  count = var.warmer_handler_function_name == null ? 0 : 1

  name                = "${aws_lambda_function.warmer_function[0].function_name}-schedule"
  schedule_expression = "cron(0/5 * * * ? *)"
  is_enabled          = true
}

resource "aws_cloudwatch_event_target" "warmer_schedule_target" {
  count = var.warmer_handler_function_name == null ? 0 : 1

  arn       = aws_lambda_function.warmer_function[0].arn
  rule      = aws_cloudwatch_event_rule.warmer_schedule_rule[0].name
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_warmer_lambda" {
  count = var.warmer_handler_function_name == null ? 0 : 1

  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.warmer_function[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.warmer_schedule_rule[0].arn
}