module "oidc_default_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-default-role"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = var.use_localstack ? [aws_iam_policy.lambda_sns_policy.arn] : [
    aws_iam_policy.oidc_default_id_token_public_key_kms_policy[0].arn,
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy[0].arn,
    aws_iam_policy.dynamo_access_policy[0].arn,
    aws_iam_policy.lambda_sns_policy.arn
  ]
}

module "oidc_sqs_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-sqs"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = [
    aws_iam_policy.lambda_sns_policy.arn
  ]
}

module "oidc_dynamo_sqs_role" {
  source      = "../modules/lambda-role"
  environment = var.environment
  role_name   = "oidc-dynamo-sqs"
  vpc_arn     = local.authentication_vpc_arn

  policies_to_attach = var.use_localstack ? [aws_iam_policy.lambda_sns_policy.arn] : [
    aws_iam_policy.audit_signing_key_lambda_kms_signing_policy[0].arn,
    aws_iam_policy.dynamo_access_policy[0].arn,
    aws_iam_policy.lambda_sns_policy.arn
  ]

}

### ID Token signing key access

data "aws_iam_policy_document" "kms_policy_document" {
  count = var.use_localstack ? 0 : 1
  statement {
    sid       = "AllowAccessToKmsSigningKey"
    effect    = "Allow"
    actions   = ["kms:GetPublicKey"]
    resources = [local.id_token_signing_key_alias_arn]
  }
}

resource "aws_iam_policy" "oidc_default_id_token_public_key_kms_policy" {
  count       = var.use_localstack ? 0 : 1
  name_prefix = "id-token-kms-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing ID token public signing key access"

  policy = data.aws_iam_policy_document.kms_policy_document[0].json
}

### Audit signing key access

data "aws_iam_policy_document" "audit_payload_kms_signing_policy_document" {
  count = var.use_localstack ? 0 : 1
  statement {
    sid       = "AllowAccessToKmsAuditSigningKey"
    effect    = "Allow"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:Verify"]
    resources = [local.audit_signing_key_arn]
  }
}

resource "aws_iam_policy" "audit_signing_key_lambda_kms_signing_policy" {
  count       = var.use_localstack ? 0 : 1
  name_prefix = "audit-payload-kms-signing-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing of audit payloads"

  policy = data.aws_iam_policy_document.audit_payload_kms_signing_policy_document[0].json
}

### Dynamo access policies

data "aws_dynamodb_table" "user_credentials_table" {
  name = "${var.environment}-user-credentials"
}

data "aws_dynamodb_table" "user_profile_table" {
  name = "${var.environment}-user-profile"
}

data "aws_dynamodb_table" "client_registry_table" {
  name = "${var.environment}-client-registry"
}

data "aws_iam_policy_document" "dynamo_access_policy_document" {
  count = var.use_localstack ? 0 : 1
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:DescribeStream",
      "dynamodb:DescribeTable",
      "dynamodb:DeleteItem",
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    resources = [
      data.aws_dynamodb_table.user_credentials_table.arn,
      data.aws_dynamodb_table.user_profile_table.arn,
      "${data.aws_dynamodb_table.user_profile_table.arn}/index/*",
      "${data.aws_dynamodb_table.user_credentials_table.arn}/index/*",
      data.aws_dynamodb_table.client_registry_table.arn,
    ]
  }
}

resource "aws_iam_policy" "dynamo_access_policy" {
  count       = var.use_localstack ? 0 : 1
  name_prefix = "dynamo-access-policy"
  path        = "/${var.environment}/oidc-default/"
  description = "IAM policy for managing Dynamo connection for a lambda"

  policy = data.aws_iam_policy_document.dynamo_access_policy_document[0].json
}