data "aws_dynamodb_table" "email_check_results_table" {
  name = "${var.environment}-email-check-result"
}

data "aws_iam_policy_document" "email_check_results_writer_dynamo_write_access" {
  statement {
    sid    = "AllowAccessToDynamoTables"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]

    resources = [
      data.aws_dynamodb_table.email_check_results_table.arn,
    ]
  }
}

resource "aws_iam_policy" "email_check_results_writer_dynamo_write_access" {
  name        = "${var.environment}-email-check-results-dynamo-access-policy"
  description = "IAM policy managing write access for the Email Check Results Writer lambda to the Email Check Results table"

  policy = data.aws_iam_policy_document.email_check_results_writer_dynamo_write_access.json
}
