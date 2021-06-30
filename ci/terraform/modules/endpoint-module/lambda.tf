resource "aws_lambda_function" "endpoint_lambda" {
  filename      = var.lambda_zip_file
  function_name = replace("${var.environment}-${var.endpoint_name}-lambda", ".", "")
  role          = var.lambda_role_arn
  handler       = var.handler_function_name
  timeout       = 30
  memory_size = 512

  source_code_hash = filebase64sha256(var.lambda_zip_file)
  vpc_config {
    security_group_ids = [var.security_group_id]
    subnet_ids = var.subnet_id
  }
  environment {
    variables = var.handler_environment_variables
  }

  runtime = var.handler_runtime

  tags = {
    environment = var.environment
  }
}
