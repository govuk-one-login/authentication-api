resource "aws_dynamodb_table" "stub_ticf_cri_table" {
  name         = "${var.environment}-stub-ticf-cri"
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

  #  server_side_encryption has not been enabled as this table contains only test data
}

data "aws_iam_policy_document" "stub_ticf_cri_dynamo_read_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
    ]

    resources = [
      aws_dynamodb_table.stub_ticf_cri_table.arn,
      "${aws_dynamodb_table.stub_ticf_cri_table.arn}/index/*",
    ]
  }
}

resource "aws_iam_policy" "stub_ticf_cri_dynamo_read_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy managing write access for the TICF CRI Stub Lambda to the Dynamo Stub TICF CRI table"

  policy = data.aws_iam_policy_document.stub_ticf_cri_dynamo_read_access.json
}
