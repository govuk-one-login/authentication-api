resource "aws_dynamodb_table" "stub_account_interventions_table" {
  name         = "${var.environment}-stub-account-interventions"
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "InternalPairwiseId"

  deletion_protection_enabled = var.dynamo_deletion_protection_enabled

  attribute {
    name = "InternalPairwiseId"
    type = "S"
  }

  lifecycle {
    prevent_destroy = false
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
  #  server_side_encryption has not been enabled as this table contains only test data
}

data "aws_iam_policy_document" "stub_interventions_dynamo_read_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
    ]

    resources = [
      aws_dynamodb_table.stub_account_interventions_table.arn,
      "${aws_dynamodb_table.stub_account_interventions_table.arn}/index/*",
    ]
  }
}

resource "aws_iam_policy" "stub_interventions_dynamo_read_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy managing write access for the Interventions Api Stub Lambda to the Dynamo Stub Interventions table"

  policy = data.aws_iam_policy_document.stub_interventions_dynamo_read_access.json
}

## DynamoDB Resource Policies
## These policies are used to allow cross-account access to the DynamoDB tables

locals {
  restricted_environments = ["production", "integration", "staging"]
  create_resource         = !contains(local.restricted_environments, var.environment)
}
resource "aws_dynamodb_resource_policy" "stub_account_interventions_table" {
  count        = local.create_resource ? 1 : 0
  resource_arn = aws_dynamodb_table.stub_account_interventions_table.arn
  policy       = data.aws_iam_policy_document.cross_account_table_resource_policy_document[0].json
}

data "aws_iam_policy_document" "cross_account_table_resource_policy_document" {
  count = local.create_resource ? 1 : 0
  statement {
    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    effect = "Allow"
    principals {
      identifiers = [var.auth_new_account_id]
      type        = "AWS"
    }
    resources = ["*"]
  }
}
