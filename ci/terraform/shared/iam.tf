# Create a new IAM role for cross account access
locals {
  allowed_environments     = ["dev", "build", "staging"]
  allow_cross_account_role = contains(local.allowed_environments, var.environment)
}

resource "aws_iam_role" "cross_account_role" {
  count       = local.allow_cross_account_role ? 1 : 0
  name        = "CrossAccountRole-new-${var.environment}"
  description = "A role to be assumed by new Build AWS account"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.auth_new_account_id}:root"
        }
      }
    ]
  })
}

data "aws_dynamodb_table" "user_credentials_table" {
  count = local.allow_cross_account_role ? 1 : 0
  name  = "${var.environment}-user-credentials"
}

data "aws_dynamodb_table" "user_profile_table" {
  count = local.allow_cross_account_role ? 1 : 0
  name  = "${var.environment}-user-profile"
}

data "aws_dynamodb_table" "stub_account_intevention_table" {
  count = local.allow_cross_account_role ? 1 : 0
  name  = "${var.environment}-stub-account-interventions"
}

data "aws_dynamodb_table" "account_modifiers_table" {
  count = local.allow_cross_account_role ? 1 : 0
  name  = "${var.environment}-account-modifiers"
}


# Create a new IAM policy for the role
data "aws_iam_policy_document" "dynamo_access_policy" {
  count = local.allow_cross_account_role ? 1 : 0
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:UpdateItem",
      "dynamodb:List*",
      "dynamodb:Get*",
      "dynamodb:DescribeTable",
      "dynamodb:PutItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:DeleteItem",
    ]
    resources = [
      data.aws_dynamodb_table.user_credentials_table[0].arn,
      data.aws_dynamodb_table.user_profile_table[0].arn,
      data.aws_dynamodb_table.stub_account_intevention_table[0].arn,
      data.aws_dynamodb_table.account_modifiers_table[0].arn,
      "arn:aws:dynamodb:eu-west-2:${var.auth_new_account_id}:table/${var.environment}-stub-account-interventions",
    ]
  }

  statement {
    sid    = "AllowAccessToKms"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey",
    ]
    resources = [
      aws_kms_key.client_registry_table_encryption_key.arn,
      aws_kms_key.user_profile_table_encryption_key.arn,
      aws_kms_key.user_credentials_table_encryption_key.arn,
      aws_kms_key.account_modifiers_table_encryption_key.arn
    ]
  }

  statement {
    sid    = "AllowAccessToKmsSigningKeys"
    effect = "Allow"
    actions = [
      "kms:GetPublicKey",
      "kms:Sign"
    ]
    resources = [
      aws_kms_key.id_token_signing_key.arn,
      "arn:aws:kms:eu-west-2:058264536367:key/*"
    ]
  }

  statement {
    sid    = "AllowAPITests"
    effect = "Allow"
    actions = [
      "apigateway:GET",
      "execute-api:*",
      "lambda:InvokeFunction",
      "s3:ListBucket",
      "s3:GetObject",
      "s3:DeleteObject"
    ]
    resources = [
      "arn:aws:apigateway:eu-west-2::/restapis",
      "arn:aws:apigateway:eu-west-2::/restapis/*",
      "arn:aws:execute-api:eu-west-2:975050272416:*",
      "arn:aws:lambda:eu-west-2:${var.auth_new_account_id}:function:${var.environment}-api_gateway_authorizer",
      "arn:aws:lambda:eu-west-2:${var.auth_new_account_id}:function:${var.environment}-authenticate-lambda",
      "arn:aws:lambda:eu-west-2:${var.auth_new_account_id}:function:${var.environment}-mfa-methods-create-lambda",
      "arn:aws:lambda:eu-west-2:${var.auth_new_account_id}:function:${var.environment}-mfa-methods-retrieve-lambda",
      "arn:aws:lambda:eu-west-2:${var.auth_new_account_id}:function:${var.environment}-mfa-methods-update-lambda",
      "arn:aws:lambda:eu-west-2:${var.auth_new_account_id}:function:${var.environment}-send-otp-notification-lambda",
      "arn:aws:lambda:eu-west-2:${data.aws_caller_identity.current.account_id}:function:${var.environment}-api_gateway_authorizer",
      "arn:aws:lambda:eu-west-2:${data.aws_caller_identity.current.account_id}:function:${var.environment}-authenticate-lambda",
      "arn:aws:lambda:eu-west-2:${data.aws_caller_identity.current.account_id}:function:${var.environment}-mfa-methods-create-lambda",
      "arn:aws:lambda:eu-west-2:${data.aws_caller_identity.current.account_id}:function:${var.environment}-mfa-methods-retrieve-lambda",
      "arn:aws:lambda:eu-west-2:${data.aws_caller_identity.current.account_id}:function:${var.environment}-mfa-methods-update-lambda",
      "arn:aws:lambda:eu-west-2:${data.aws_caller_identity.current.account_id}:function:${var.environment}-send-otp-notification-lambda",
      "arn:aws:s3:::${var.environment}-am-api-acceptance-tests-otp",
      "arn:aws:s3:::${var.environment}-am-api-acceptance-tests-otp/*",
      "arn:aws:s3:::${var.environment}-am-api-acceptance-test-otp",
      "arn:aws:s3:::${var.environment}-am-api-acceptance-test-otp/*"
    ]
  }
}

# Create  policy to the role
resource "aws_iam_policy" "dynamo_access_policy" {
  count       = local.allow_cross_account_role ? 1 : 0
  name        = "${var.environment}-dynamo-access-policy"
  path        = "/"
  description = "IAM policy access to dyanama table"

  policy = data.aws_iam_policy_document.dynamo_access_policy[0].json
}


# Attach the policy to the role
resource "aws_iam_role_policy_attachment" "cross_account_attach" {
  count      = local.allow_cross_account_role ? 1 : 0
  role       = aws_iam_role.cross_account_role[0].name
  policy_arn = aws_iam_policy.dynamo_access_policy[0].arn
}
