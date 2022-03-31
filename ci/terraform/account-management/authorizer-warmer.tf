module "lambda_warmer_role" {
  count  = var.keep_lambdas_warm ? 1 : 0
  source = "../modules/lambda-role"

  environment = var.environment
  role_name   = "lambda-warmer"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    aws_iam_policy.lambda_warmer_policy[0].arn
  ]
}

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

resource "aws_iam_policy" "lambda_warmer_policy" {
  count = var.keep_lambdas_warm ? 1 : 0

  name        = "${aws_lambda_function.authorizer.function_name}-warmer-policy"
  policy      = data.aws_iam_policy_document.warmer_can_execute_endpoint_lambda.json
  description = "Allow warmer to invoke its related function"
}

resource "aws_lambda_function" "warmer_function" {
  count = var.keep_lambdas_warm ? 1 : 0

  function_name = "${aws_lambda_function.authorizer.function_name}-lambda-warmer"
  role          = module.lambda_warmer_role[0].arn
  handler       = "uk.gov.di.lambdawarmer.lambda.LambdaWarmerHandler::handleRequest"
  timeout       = 60
  memory_size   = 1024

  tracing_config {
    mode = "Active"
  }

  s3_bucket         = aws_s3_bucket.source_bucket.bucket
  s3_key            = aws_s3_bucket_object.warmer_release_zip.key
  s3_object_version = aws_s3_bucket_object.warmer_release_zip.version_id

  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  vpc_config {
    security_group_ids = [local.allow_aws_service_access_security_group_id]
    subnet_ids         = local.private_subnet_ids
  }

  environment {
    variables = {
      LAMBDA_ARN             = aws_lambda_function.authorizer.arn
      LAMBDA_QUALIFIER       = aws_lambda_alias.authorizer_alias.name
      LAMBDA_TYPE            = "AUTHORIZER"
      LAMBDA_MIN_CONCURRENCY = var.lambda_min_concurrency
      JAVA_TOOL_OPTIONS      = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1"
    }
  }
  kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn

  runtime = "java11"

  tags = merge(local.default_tags, {
    lambda = "warmer"
  })
}

resource "aws_cloudwatch_log_group" "warmer_lambda_log_group" {
  count = var.keep_lambdas_warm ? 1 : 0

  name              = "/aws/lambda/${aws_lambda_function.warmer_function[0].function_name}"
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

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

  statement_id_prefix = "AllowExecutionFromCloudWatchScheduleRule"

  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.warmer_function[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.warmer_schedule_rule[0].arn
}

resource "aws_cloudwatch_event_rule" "warmer_deployment_trigger_rule" {
  count = var.keep_lambdas_warm ? 1 : 0

  name = "${aws_lambda_function.warmer_function[0].function_name}-on-deploy"
  event_pattern = jsonencode({
    "source" : [
      "aws.lambda"
    ],
    "detail-type" : [
      "AWS API Call via CloudTrail"
    ],
    "detail" : {
      "eventSource" : [
        "lambda.amazonaws.com"
      ],
      "eventName" : [
        "UpdateAlias20150331"
      ],
      "requestParameters" : {
        "functionName" : [
          aws_lambda_function.authorizer.arn
        ]
      }
    }
  })

  is_enabled = true
}

resource "aws_cloudwatch_event_target" "warmer_deployment_target" {
  count = var.keep_lambdas_warm ? 1 : 0

  arn  = aws_lambda_function.warmer_function[0].arn
  rule = aws_cloudwatch_event_rule.warmer_deployment_trigger_rule[0].name
}

resource "aws_lambda_permission" "allow_cloudwatch_deployment_rule_to_call_warmer_lambda" {
  count = var.keep_lambdas_warm ? 1 : 0

  statement_id_prefix = "AllowExecutionFromCloudWatchDeploymentRule-"

  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.warmer_function[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.warmer_deployment_trigger_rule[0].arn
}
