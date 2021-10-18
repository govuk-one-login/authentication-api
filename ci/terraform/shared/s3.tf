resource "aws_s3_bucket" "smoketest_sms_bucket" {
  bucket = "${var.environment}-smoke-test-sms-codes"

  acl = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = local.default_tags
}

resource "aws_iam_policy" "s3_smoketest_policy" {
  count       = var.use_localstack ? 0 : 1
  name        = "${var.environment}-s3-smoketest-policy"
  path        = "/"
  description = "IAM policy for managing S3 connection to the S3 Smoketest bucket"

  policy = data.aws_iam_policy_document.s3_smoketest_policy_document[0].json
}

data "aws_iam_policy_document" "s3_smoketest_policy_document" {
  count = var.use_localstack ? 0 : 1
  statement {
    sid    = "AllowAccessToWriteToS3"
    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]
    resources = [
      aws_s3_bucket.smoketest_sms_bucket.arn,
    ]
  }
}

resource "aws_iam_role_policy_attachment" "notification_lambda_smoketest_s3" {
  count      = var.use_localstack ? 0 : 1
  role       = aws_iam_role.email_lambda_iam_role.name
  policy_arn = aws_iam_policy.s3_smoketest_policy[0].arn
}
