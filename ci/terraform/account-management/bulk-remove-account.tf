module "account_management_bulk_remove_account_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "account-management-bulk-remove-account-role"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    aws_iam_policy.dynamo_am_user_read_access_policy.arn,
    aws_iam_policy.dynamo_am_user_delete_access_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    module.account_management_txma_audit.access_policy_arn,
    aws_iam_policy.dynamo_am_account_modifiers_read_access_policy.arn,
    aws_iam_policy.dynamo_am_account_modifiers_delete_access_policy.arn,
    local.account_modifiers_encryption_policy_arn,
    aws_iam_policy.permit_send_email_queue_policy.arn,
    aws_iam_policy.legacy_account_deletion_topic.arn
  ]
  extra_tags = {
    Service = "bulk-remove-account"
  }
}

resource "aws_lambda_function" "bulk_remove_account_lambda" {
  function_name = replace("${var.environment}-bulk-remove-account-lambda", ".", "")
  role          = module.account_management_bulk_remove_account_role.arn
  handler       = "uk.gov.di.accountmanagement.lambda.BulkRemoveAccountHandler::handleRequest"
  timeout       = 30
  publish       = true


  s3_bucket               = aws_s3_bucket.source_bucket.bucket
  s3_key                  = aws_s3_object.account_management_api_release_zip.key
  s3_object_version       = aws_s3_object.account_management_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  vpc_config {
    security_group_ids = [
      local.allow_aws_service_access_security_group_id,
      aws_security_group.allow_access_to_am_redis.id,
    ]
    subnet_ids = local.private_subnet_ids
  }

  environment {
    variables = {
      JAVA_TOOL_OPTIONS                 = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1 '--add-reads=jdk.jfr=ALL-UNNAMED'"
      ENVIRONMENT                       = var.environment
      EMAIL_QUEUE_URL                   = aws_sqs_queue.email_queue.id
      TXMA_AUDIT_QUEUE_URL              = module.account_management_txma_audit.queue_url
      INTERNAl_SECTOR_URI               = var.internal_sector_uri
      LEGACY_ACCOUNT_DELETION_TOPIC_ARN = local.bulk_remove_account_deletion_topic_arn
    }
  }

  kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  runtime     = "java17"

  depends_on = [module.account_management_bulk_remove_account_role]
}

resource "aws_cloudwatch_log_group" "bulk_remove_account_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.bulk_remove_account_lambda.function_name}"
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.bulk_remove_account_lambda
  ]
}

resource "aws_cloudwatch_log_subscription_filter" "bulk_remove_account_log_subscription" {
  count           = length(var.logging_endpoint_arns)
  name            = "bulk_remove_account-log-subscription-${count.index}"
  log_group_name  = aws_cloudwatch_log_group.bulk_remove_account_lambda_log_group.name
  filter_pattern  = ""
  destination_arn = var.logging_endpoint_arns[count.index]

  lifecycle {
    create_before_destroy = false
  }
}

data "aws_iam_policy_document" "invoke_bulk_remove_account_lambda" {
  statement {
    sid       = "permitInvokeBulkRemoveAccountLambda"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.bulk_remove_account_lambda.arn]

  }
}

resource "aws_iam_policy" "invoke_bulk_remove_account_lambda" {
  count       = local.should_create_bulk_remove_account_policy ? 1 : 0
  name        = "bulk-remove-account-user-policy"
  path        = "/control-tower/am/"
  description = "Policy for use in Control Tower to be attached to the role assumed by support users to bulk account deletions"
  policy      = data.aws_iam_policy_document.invoke_bulk_remove_account_lambda.json
}

locals {
  bulk_remove_mock_topic_arn                        = try(aws_sns_topic.mock_account_deletion_topic[0].arn, "")
  bulk_remove_account_deletion_topic_arn            = coalesce(var.legacy_account_deletion_topic_arn, local.bulk_remove_mock_topic_arn)
  should_create_bulk_remove_account_policy = contains(["production", "integration", "staging"], var.environment)
}
