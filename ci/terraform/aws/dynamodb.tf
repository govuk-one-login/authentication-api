resource "aws_dynamodb_table" "user_credentials_table" {
  name           = "${var.environment}-user-credentials"
  billing_mode   = "PROVISIONED"
  write_capacity = 5
  read_capacity  = 5
  hash_key       = "Email"

  attribute {
    name = "Email"
    type = "S"
  }

  attribute {
    name = "SubjectID"
    type = "S"
  }

  global_secondary_index {
    name               = "SubjectIDIndex"
    hash_key           = "SubjectID"
    write_capacity     = 5
    read_capacity      = 5
    projection_type    = "ALL"
  }

  server_side_encryption {
    enabled = true
  }
}

resource "aws_dynamodb_table" "user_profile_table" {
  name           = "${var.environment}-user-profile"
  billing_mode   = "PROVISIONED"
  write_capacity = 5
  read_capacity  = 5
  hash_key       = "Email"

  attribute {
    name = "Email"
    type = "S"
  }

  attribute {
    name = "SubjectID"
    type = "S"
  }

  global_secondary_index {
    name               = "SubjectIDIndex"
    hash_key           = "SubjectID"
    write_capacity     = 5
    read_capacity      = 5
    projection_type    = "ALL"
  }

  server_side_encryption {
    enabled = true
  }
}

resource "aws_dynamodb_table" "client_registry_table" {
  name           = "${var.environment}-client-registry"
  billing_mode   = "PROVISIONED"
  write_capacity = 5
  read_capacity  = 5
  hash_key       = "ClientID"

  attribute {
    name = "ClientID"
    type = "S"
  }

  attribute {
    name = "ClientName"
    type = "S"
  }

  global_secondary_index {
    name               = "ClientNameIndex"
    hash_key           = "ClientName"
    write_capacity     = 5
    read_capacity      = 5
    projection_type    = "ALL"
  }
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
      aws_dynamodb_table.client_registry_table.arn
    ]
  }
}

resource "aws_iam_policy" "lambda_dynamo_policy" {
  count = var.use_localstack ? 0 : 1
  name        = "${var.environment}-standard-lambda-dynamo-policy"
  path        = "/"
  description = "IAM policy for managing Dynamo connection for a lambda"

  policy = data.aws_iam_policy_document.dynamo_policy_document[0].json
}

resource "aws_iam_role_policy_attachment" "lambda_dynamo" {
  count = var.use_localstack ? 0 : 1
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_dynamo_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "lambda_sqs_dynamo" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.dynamo_sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_dynamo_policy[0].arn
}
