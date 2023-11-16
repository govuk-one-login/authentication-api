resource "aws_dynamodb_table" "stub_account_interventions_table" {
  name         = "${var.environment}-stub-account-interventions"
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "InternalPairwiseId"

  attribute {
    name = "InternalPairwiseId"
    type = "S"
  }

  lifecycle {
    prevent_destroy = false
  }

  #  server_side_encryption has not been enabled as this table contains only test data

  tags = local.default_tags
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
