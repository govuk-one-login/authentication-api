module "account_notification_default_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "account-management-default-role"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    aws_iam_policy.lambda_kms_policy.arn,
    aws_iam_policy.lambda_dynamo_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.parameter_policy.arn
  ]
}

module "account_notification_dynamo_sqs_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "account-management-dynamo-sqs"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    aws_iam_policy.lambda_dynamo_policy.arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn,
    aws_iam_policy.parameter_policy.arn
  ]
}

### ID token key permissions

data "aws_kms_key" "id_token_public_key" {
  key_id = "alias/${var.environment}-id-token-signing-key-alias"
}

data "aws_iam_policy_document" "kms_policy_document" {
  statement {
    sid    = "AllowAccessToKmsPublicKey"
    effect = "Allow"

    actions = [
      "kms:GetPublicKey",
    ]
    resources = [
      data.aws_kms_key.id_token_public_key.arn,
    ]
  }
}

resource "aws_iam_policy" "lambda_kms_policy" {
  name        = "${var.environment}--account-mgmt-lambda-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda"

  policy = data.aws_iam_policy_document.kms_policy_document.json
}

### DynamoDB permissions
data "aws_iam_policy_document" "dynamo_policy_document" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:GetItem",
      "dynamodb:UpdateItem",
      "dynamodb:DescribeTable",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
    ]
    resources = [
      data.aws_dynamodb_table.user_credentials_table.arn,
      data.aws_dynamodb_table.user_profile_table.arn,
      data.aws_dynamodb_table.client_registry_table.arn,
      "${data.aws_dynamodb_table.user_profile_table.arn}/index/*",
    ]
  }
}

resource "aws_iam_policy" "lambda_dynamo_policy" {
  name        = "${var.environment}-account-management-lambda-dynamo-policy"
  path        = "/"
  description = "IAM policy for managing Dynamo connection for an account management lambdas"

  policy = data.aws_iam_policy_document.dynamo_policy_document.json
}

### Audit signing key permissions

data "aws_iam_policy_document" "account_management_audit_payload_kms_signing_policy_document" {
  statement {
    sid    = "AllowAccessToKmsAuditSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
      "kms:Verify"
    ]
    resources = [
      local.audit_signing_key_arn
    ]
  }

  statement {
    effect = "Allow"
    sid    = "GiveEventsSnsTopicPolicyPublish"
    actions = [
      "SNS:Publish",
      "SNS:RemovePermission",
      "SNS:SetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:Receive",
      "SNS:AddPermission",
      "SNS:Subscribe"
    ]
    resources = [data.aws_sns_topic.events.arn]
  }

  statement {
    effect = "Allow"
    sid    = "AllowLambdasToEncryptWithCustomKey"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      local.events_topic_encryption_key_arn
    ]
  }
}

resource "aws_iam_policy" "audit_signing_key_lambda_kms_signing_policy" {
  name        = "${var.environment}-account-management-lambda-audit-payload-kms-signing-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing of audit payloads"

  policy = data.aws_iam_policy_document.account_management_audit_payload_kms_signing_policy_document.json
}