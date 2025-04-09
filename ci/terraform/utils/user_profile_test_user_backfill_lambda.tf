module "user_profile_test_user_backfill_lambda_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "user-profile-test-user-backfill-lambda-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = []
}

resource "aws_lambda_function" "user_profile_test_user_backfill_lambda" {
  function_name                  = "${var.environment}-user-profile-test-user-backfill-lambda"
  role                           = module.user_profile_test_user_backfill_lambda_role.arn
  handler                        = "uk.gov.di.authentication.utils.lambda.UserProfileTestUserBackfill::handleRequest"
  timeout                        = 15 * 60
  memory_size                    = 1024
  reserved_concurrent_executions = 1
  runtime                        = "java17"

  s3_bucket         = aws_s3_object.utils_release_zip.bucket
  s3_key            = aws_s3_object.utils_release_zip.key
  s3_object_version = aws_s3_object.utils_release_zip.version_id

  kms_key_arn             = local.lambda_env_vars_encryption_kms_key_arn
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  vpc_config {
    security_group_ids = [local.authentication_security_group_id]
    subnet_ids         = local.authentication_private_subnet_ids
  }

  environment {
    variables = {
      ENVIRONMENT = var.environment
    }
  }
}

resource "aws_cloudwatch_log_group" "user_profile_test_user_backfill_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.user_profile_test_user_backfill_lambda.function_name}"
  kms_key_id        = local.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention
}
