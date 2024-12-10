data "aws_iam_policy_document" "client_registry_read_only" {
  statement {
    sid    = "ClientRegistryReadOnly"
    effect = "Allow"
    actions = [
      "dynamodb:DescribeImport",
      "dynamodb:ListTables",
      "dynamodb:DescribeContributorInsights",
      "dynamodb:ListTagsOfResource",
      "dynamodb:DescribeReservedCapacityOfferings",
      "dynamodb:PartiQLSelect",
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:DescribeContinuousBackups",
      "dynamodb:DescribeExport",
      "dynamodb:ListImports",
      "dynamodb:DescribeKinesisStreamingDestination",
      "dynamodb:ListExports",
      "dynamodb:DescribeLimits",
      "dynamodb:BatchGetItem",
      "dynamodb:ConditionCheckItem",
      "dynamodb:ListBackups",
      "dynamodb:Scan",
      "dynamodb:Query",
      "dynamodb:DescribeStream",
      "dynamodb:DescribeTimeToLive",
      "dynamodb:ListStreams",
      "dynamodb:ListContributorInsights",
      "dynamodb:DescribeGlobalTableSettings",
      "dynamodb:ListGlobalTables",
      "dynamodb:GetShardIterator",
      "dynamodb:DescribeGlobalTable",
      "dynamodb:DescribeReservedCapacity",
      "dynamodb:DescribeBackup",
      "dynamodb:DescribeEndpoints",
      "dynamodb:GetRecords",
      "dynamodb:DescribeTableReplicaAutoScaling"
    ]
    resources = [aws_dynamodb_table.client_registry_table.arn]
  }

  statement {
    sid       = "AllowListAllTables"
    effect    = "Allow"
    actions   = ["dynamodb:ListTables"]
    resources = ["arn:aws:dynamodb:eu-west-2:${data.aws_caller_identity.current.account_id}:table/*"]
  }

  statement {
    sid       = "ClientRegistryKeyDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.client_registry_table_encryption_key.arn]
  }
}

locals {
  should_create_client_registry_policy = contains(["production", "integration", "staging"], var.environment)
}

resource "aws_iam_policy" "client_registry_read_only" {
  count       = local.should_create_client_registry_policy ? 1 : 0
  name_prefix = "client-registry-read-only-user-policy"
  path        = "/control-tower/shared/"
  description = "Policy for use in Control Tower to be attached to the role assumed by support users to view the Client Registry"
  policy      = data.aws_iam_policy_document.client_registry_read_only.json
}
