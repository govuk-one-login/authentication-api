data "aws_iam_policy_document" "user_profile_stream_access" {
  statement {
    sid    = "AllowAccessToUserProfileDynamoStreamOnly"
    effect = "Allow"

    actions = [
      "dynamodb:DescribeStream",
      "dynamodb:GetRecords",
      "dynamodb:GetShardIterator",
      "dynamodb:ListStreams"
    ]

    resources = [
      data.aws_dynamodb_table.user_profile.stream_arn,
    ]
  }
}

resource "aws_iam_policy" "user_profile_stream_access" {
  name_prefix = "dynamo-access-policy"
  description = "IAM policy for managing stream read permissions to the Dynamo User Profile table"

  policy = data.aws_iam_policy_document.user_profile_stream_access.json
}