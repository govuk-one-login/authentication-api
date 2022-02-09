resource "aws_kms_key" "data_transfer_key" {
  count = var.use_localstack ? 0 : 1

  description             = "${var.environment} data transfer encyption key"
  deletion_window_in_days = 10

  tags = local.default_tags
}

resource "aws_s3_bucket" "data_transfer_bucket" {
  count = var.use_localstack ? 0 : 1

  bucket = "${var.environment}-account-transfer-bucket"

  acl = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.data_transfer_key[0].arn
      }
    }
  }

  tags = local.default_tags
}

data "aws_iam_policy_document" "data_transfer_lambda_s3_policy" {
  count = var.use_localstack ? 0 : 1

  version = "2012-10-17"
  statement {
    sid = "AllowDataTransferLambdaToGetDataFromS3"
    actions = [
      "s3:GetObject"
    ]
    resources = [
      "${aws_s3_bucket.data_transfer_bucket[0].arn}/*"
    ]
    effect = "Allow"
  }

  statement {
    sid = "AllowDataTransferLambdaToDecrypt"
    actions = [
      "kms:Decrypt"
    ]
    resources = [
      aws_kms_key.data_transfer_key[0].arn
    ]
    effect = "Allow"
  }
}

resource "aws_iam_policy" "data_transfer_s3_policy" {
  count = var.use_localstack ? 0 : 1

  name        = "${var.environment}-data-transfer-lambda-s3-policy"
  description = "IAM policy allowing data transfer lambda to access S3"
  policy      = data.aws_iam_policy_document.data_transfer_lambda_s3_policy[0].json
}

resource "aws_iam_role" "data_transfer_lambda_role" {
  count = var.use_localstack ? 0 : 1

  name = "${var.environment}-data-transfer-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json
}

resource "aws_iam_role_policy_attachment" "data_transfer_logging" {
  count = var.use_localstack ? 0 : 1

  role       = aws_iam_role.data_transfer_lambda_role[0].name
  policy_arn = aws_iam_policy.endpoint_logging_policy.arn
}

resource "aws_iam_role_policy_attachment" "data_transfer_networking" {
  count = var.use_localstack ? 0 : 1

  role       = aws_iam_role.data_transfer_lambda_role[0].name
  policy_arn = aws_iam_policy.endpoint_networking_policy.arn
}

resource "aws_iam_role_policy_attachment" "data_transfer_s3" {
  count = var.use_localstack ? 0 : 1

  role       = aws_iam_role.data_transfer_lambda_role[0].name
  policy_arn = aws_iam_policy.data_transfer_s3_policy[0].arn
}

resource "aws_lambda_function" "data_transfer_lambda" {
  count = var.use_localstack ? 0 : 1

  filename      = var.account_migration_lambda_zip_file
  function_name = "${var.environment}-account-transfer-lambda"
  role          = aws_iam_role.data_transfer_lambda_role[0].arn
  handler       = "uk.gov.di.authentication.accountmigration.DataMigrationHandler::handleRequest"
  memory_size   = 8192
  timeout       = 900

  tracing_config {
    mode = "Active"
  }

  source_code_hash = filebase64sha256(var.account_migration_lambda_zip_file)
  vpc_config {
    security_group_ids = [local.allow_aws_service_access_security_group_id]
    subnet_ids         = local.private_subnet_ids
  }
  environment {
    variables = {
      ENVIRONMENT              = var.environment
      TERMS_CONDITIONS_VERSION = var.terms_and_conditions
    }
  }
  kms_key_arn = aws_kms_key.lambda_env_vars_encryption_key.arn

  runtime = "java11"

  tags = local.default_tags
}

resource "aws_cloudwatch_log_group" "data_transfer_lambda_log_group" {
  count = var.use_localstack ? 0 : 1

  name              = "/aws/lambda/${aws_lambda_function.data_transfer_lambda[0].function_name}"
  tags              = local.default_tags
  kms_key_id        = aws_kms_key.cloudwatch_log_encryption.arn
  retention_in_days = 5

  depends_on = [
    aws_lambda_function.data_transfer_lambda
  ]
}

resource "aws_lambda_permission" "allow_bucket_to_invoke_function" {
  count = var.use_localstack ? 0 : 1

  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.data_transfer_lambda[0].arn
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.data_transfer_bucket[0].arn
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  count = var.use_localstack ? 0 : 1

  bucket = aws_s3_bucket.data_transfer_bucket[0].id

  lambda_function {
    lambda_function_arn = aws_lambda_function.data_transfer_lambda[0].arn
    events = [
      "s3:ObjectCreated:*"
    ]
    filter_prefix = "data_transfer_"
    filter_suffix = ".csv"
  }

  depends_on = [
    aws_lambda_permission.allow_bucket_to_invoke_function,
  ]
}
