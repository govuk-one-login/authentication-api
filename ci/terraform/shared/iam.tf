

# Create a new IAM role for cross account access
resource "aws_iam_role" "cross_account_role" {
  count       = var.environment == "build" ? 1 : 0
  name        = "CrossAccountRole-new-build"
  description = "A role to be assumed by new Build AWS account"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::058264536367:root"
        }
      }
    ]
  })
}

data "aws_dynamodb_table" "user_credentials_table" {
  name = "${var.environment}-user-credentials"
}

data "aws_dynamodb_table" "user_profile_table" {
  name = "${var.environment}-user-profile"
}

data "aws_dynamodb_table" "stub_account_intevention_table" {
  name = "${var.environment}-stub-account-interventions"
}

data "aws_dynamodb_table" "account_modifiers_table" {
  name = "${var.environment}-account-modifiers"
}


# Create a new IAM policy for the role
data "aws_iam_policy_document" "dynamo_access_policy" {
  count = var.environment == "build" ? 1 : 0
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:UpdateItem",
      "dynamodb:DescribeTable",
      "dynamodb:PutItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:DeleteItem",
    ]
    resources = [
      data.aws_dynamodb_table.user_credentials_table.arn,
      data.aws_dynamodb_table.user_profile_table.arn,
      data.aws_dynamodb_table.stub_account_intevention_table.arn,
      data.aws_dynamodb_table.account_modifiers_table.arn,
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
      aws_kms_key.account_modifiers_table_encryption_key.arn
    ]
  }
}

# Create  policy to the role
resource "aws_iam_policy" "dynamo_access_policy" {
  count       = var.environment == "build" ? 1 : 0
  name        = "${var.environment}-dynamo-access-policy"
  path        = "/"
  description = "IAM policy access to dyanama table"

  policy = data.aws_iam_policy_document.dynamo_access_policy[0].json
}


# Attach the policy to the role
resource "aws_iam_role_policy_attachment" "cross_account_attach" {
  count      = var.environment == "build" ? 1 : 0
  role       = aws_iam_role.cross_account_role[0].name
  policy_arn = aws_iam_policy.dynamo_access_policy[0].arn
}
