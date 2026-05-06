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
  extra_tags = {
    Service = "manually-delete-account"
  }
}

module "manually_delete_account" {
  source = "../modules/endpoint-lambda"

  endpoint_name         = "manually-delete-account"
  handler_function_name = "uk.gov.di.accountmanagement.lambda.ManuallyDeleteAccountHandler::handleRequest"

  memory_size                 = lookup(var.performance_tuning, "manually-delete-account", local.default_performance_parameters).memory
  provisioned_concurrency     = lookup(var.performance_tuning, "manually-delete-account", local.default_performance_parameters).concurrency
  max_provisioned_concurrency = lookup(var.performance_tuning, "manually-delete-account", local.default_performance_parameters).max_concurrency
  scaling_trigger             = lookup(var.performance_tuning, "manually-delete-account", local.default_performance_parameters).scaling_trigger

  source_bucket           = aws_s3_bucket.source_bucket.bucket
  lambda_zip_file         = aws_s3_object.account_management_api_release_zip.key
  lambda_zip_file_version = aws_s3_object.account_management_api_release_zip.version_id
  code_signing_config_arn = local.lambda_code_signing_configuration_arn

  security_group_ids = concat([
    local.allow_aws_service_access_security_group_id,
  ], var.environment == "production" ? [aws_security_group.allow_access_to_am_redis.id] : [])
  subnet_id = local.private_subnet_ids

  environment                            = var.environment
  lambda_role_arn                        = module.account_management_manually_delete_account_role.arn
  logging_endpoint_arns                  = var.logging_endpoint_arns
  cloudwatch_key_arn                     = data.terraform_remote_state.shared.outputs.cloudwatch_encryption_key_arn
  cloudwatch_log_retention               = var.cloudwatch_log_retention
  lambda_env_vars_encryption_kms_key_arn = data.terraform_remote_state.shared.outputs.lambda_env_vars_encryption_kms_key_arn

  account_alias         = local.aws_account_alias
  slack_event_topic_arn = local.slack_event_sns_topic_arn
  dynatrace_secret      = local.dynatrace_secret

  lambda_error_alarm_disabled      = true
  lambda_error_rate_alarm_disabled = true

  handler_environment_variables = {
    JAVA_TOOL_OPTIONS                 = "-XX:+TieredCompilation -XX:TieredStopAtLevel=1 '--add-reads=jdk.jfr=ALL-UNNAMED'"
    ENVIRONMENT                       = var.environment
    EMAIL_QUEUE_URL                   = aws_sqs_queue.email_queue.id
    TXMA_AUDIT_QUEUE_URL              = module.account_management_txma_audit.queue_url
    INTERNAl_SECTOR_URI               = var.internal_sector_uri
    LEGACY_ACCOUNT_DELETION_TOPIC_ARN = local.account_deletion_topic_arn
  }
  depends_on = [module.account_management_manually_delete_account_role]
}

data "aws_iam_policy_document" "invoke_account_deletion_lambda" {
  statement {
    sid       = "permitInvokeLambda"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction", "lambda:GetFunctionConfiguration"]
    resources = [module.manually_delete_account.function_arn]
  }
}

resource "aws_iam_policy" "invoke_account_deletion_lambda" {
  count       = local.should_create_account_deletion_policy ? 1 : 0
  name        = "manual-account-deletion-user-policy"
  path        = "/control-tower/am/"
  description = "Policy for use in Control Tower to be attached to the role assumed by support users to perform account deletions"
  policy      = data.aws_iam_policy_document.invoke_account_deletion_lambda.json
}

resource "aws_iam_role" "account_deletion_role" {
  count       = local.should_create_account_deletion_policy ? 1 : 0
  name        = "support-account-deletion-role"
  path        = "/runbooks/"
  description = "Role for support users to perform account deletions using lambda exec action"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringLike = {
          "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_ApprovedServiceSupport*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "account_deletion_policy" {
  count      = local.should_create_account_deletion_policy ? 1 : 0
  role       = aws_iam_role.account_deletion_role[0].name
  policy_arn = aws_iam_policy.invoke_account_deletion_lambda[0].arn
}

locals {
  mock_topic_arn                        = try(aws_sns_topic.mock_account_deletion_topic[0].arn, "")
  account_deletion_topic_arn            = coalesce(var.legacy_account_deletion_topic_arn, local.mock_topic_arn)
  should_create_account_deletion_policy = contains(["production", "integration", "staging"], var.environment)
}
