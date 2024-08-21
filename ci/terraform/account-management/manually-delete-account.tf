module "account_management_manually_delete_account_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "account-management-manually-delete-account-role"
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
}

resource "aws_lambda_function" "manually_delete_account_lambda" {
  function_name = replace("${var.environment}-manually-delete-account-lambda", ".", "")
  role          = module.account_management_manually_delete_account_role.arn
  handler       = "uk.gov.di.accountmanagement.lambda.ManuallyDeleteAccountHandler::handleRequest"
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
      JAVA_TOOL_OPTIONS                 = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1"
      ENVIRONMENT                       = var.environment
      EMAIL_QUEUE_URL                   = aws_sqs_queue.email_queue.id
      TXMA_AUDIT_QUEUE_URL              = module.account_management_txma_audit.queue_url
      INTERNAl_SECTOR_URI               = var.internal_sector_uri
      LEGACY_ACCOUNT_DELETION_TOPIC_ARN = local.account_deletion_topic_arn
    }
  }

  kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn
  runtime     = "java17"

  tags = local.default_tags

  depends_on = [module.account_management_manually_delete_account_role]
}

resource "aws_cloudwatch_log_group" "manually_delete_account_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.manually_delete_account_lambda.function_name}"
  tags              = local.default_tags
  kms_key_id        = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  retention_in_days = var.cloudwatch_log_retention

  depends_on = [
    aws_lambda_function.manually_delete_account_lambda
  ]
}

data "aws_iam_policy_document" "permit_send_email_queue_policy_document" {
  statement {
    sid    = "SendSQS"
    effect = "Allow"


    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.email_queue.arn
    ]
  }
}

resource "aws_iam_policy" "permit_send_email_queue_policy" {
  name_prefix = "permit-send-email-queue-policy"
  path        = "/${var.environment}/am/"
  description = "IAM policy to allow sending messages to the account management email queue"

  policy = data.aws_iam_policy_document.permit_send_email_queue_policy_document.json
}

data "aws_iam_policy_document" "legacy_account_deletion_topic" {
  statement {
    sid    = "SendAccountDeletionSNS"
    effect = "Allow"

    actions = [
      "sns:Publish"
    ]

    resources = [
      local.account_deletion_topic_arn
    ]
  }
}

resource "aws_iam_policy" "legacy_account_deletion_topic" {
  name_prefix = "permit-send-legacy-account-deletion-topic"
  path        = "/${var.environment}/am/"
  description = "Allow the manual account deletion lambda to post to the SNS topic owned by Home"
  policy      = data.aws_iam_policy_document.legacy_account_deletion_topic.json
}

resource "aws_sns_topic" "mock_account_deletion_topic" {
  count = var.legacy_account_deletion_topic_arn == null ? 1 : 0
  name  = "${var.environment}-mock-account-deletion-topic"
}

locals {
  account_deletion_topic_arn = coalesce(var.legacy_account_deletion_topic_arn, aws_sns_topic.mock_account_deletion_topic[0].arn)
}
