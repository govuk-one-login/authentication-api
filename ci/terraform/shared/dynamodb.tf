resource "aws_dynamodb_table" "user_credentials_table" {
  name         = "${var.environment}-user-credentials"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "Email"

  attribute {
    name = "Email"
    type = "S"
  }

  attribute {
    name = "SubjectID"
    type = "S"
  }

  global_secondary_index {
    name            = "SubjectIDIndex"
    hash_key        = "SubjectID"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled = !var.use_localstack
  }

  point_in_time_recovery {
    enabled = !var.use_localstack
  }

  lifecycle {
    prevent_destroy = var.prevent_destroy_of_data
  }

  tags = local.default_tags

}

resource "aws_dynamodb_table" "user_profile_table" {
  name         = "${var.environment}-user-profile"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "Email"

  attribute {
    name = "Email"
    type = "S"
  }

  attribute {
    name = "SubjectID"
    type = "S"
  }

  attribute {
    name = "PublicSubjectID"
    type = "S"
  }

  global_secondary_index {
    name            = "SubjectIDIndex"
    hash_key        = "SubjectID"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "PublicSubjectIDIndex"
    hash_key        = "PublicSubjectID"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled = !var.use_localstack
  }

  point_in_time_recovery {
    enabled = !var.use_localstack
  }

  lifecycle {
    prevent_destroy = var.prevent_destroy_of_data
  }

  tags = local.default_tags
}

resource "aws_dynamodb_table" "client_registry_table" {
  name         = "${var.environment}-client-registry"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ClientID"

  attribute {
    name = "ClientID"
    type = "S"
  }

  attribute {
    name = "ClientName"
    type = "S"
  }

  global_secondary_index {
    name            = "ClientNameIndex"
    hash_key        = "ClientName"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = !var.use_localstack
  }

  server_side_encryption {
    enabled = !var.use_localstack
  }

  lifecycle {
    prevent_destroy = var.prevent_destroy_of_data
  }

  tags = local.default_tags
}

data "aws_iam_policy_document" "dynamo_policy_document" {
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
      aws_dynamodb_table.user_credentials_table.arn,
      aws_dynamodb_table.user_profile_table.arn,
      "${aws_dynamodb_table.user_profile_table.arn}/index/*",
      "${aws_dynamodb_table.user_credentials_table.arn}/index/*",
      aws_dynamodb_table.client_registry_table.arn,
    ]
  }
}

resource "aws_iam_policy" "lambda_dynamo_policy" {
  count       = var.use_localstack ? 0 : 1
  name        = "${var.environment}-standard-lambda-dynamo-policy"
  path        = "/"
  description = "IAM policy for managing Dynamo connection for a lambda"

  policy = data.aws_iam_policy_document.dynamo_policy_document[0].json
}

resource "aws_iam_role_policy_attachment" "lambda_dynamo" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_dynamo_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "token_lambda_dynamo" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.token_lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_dynamo_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "lambda_sqs_dynamo" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.dynamo_sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_dynamo_policy[0].arn
}
