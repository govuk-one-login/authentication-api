resource "aws_s3_bucket" "smoketest_sms_bucket" {
  bucket = "${var.environment}-smoke-test-sms-codes"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "smoketest_sms_bucket" {
  bucket = aws_s3_bucket.smoketest_sms_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "smoketest_sms_bucket" {
  bucket = aws_s3_bucket.smoketest_sms_bucket.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }

}

resource "aws_s3_bucket_public_access_block" "smoke-test_private_bucket" {
  bucket                  = aws_s3_bucket.smoketest_sms_bucket.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_iam_policy" "s3_smoketest_policy" {
  name        = "${var.environment}-s3-smoketest-policy"
  path        = "/"
  description = "IAM policy for managing S3 connection to the S3 Smoketest bucket"

  policy = data.aws_iam_policy_document.s3_smoketest_policy_document.json
}
moved {
  from = aws_iam_policy.s3_smoketest_policy[0]
  to   = aws_iam_policy.s3_smoketest_policy
}

data "aws_iam_policy_document" "s3_smoketest_policy_document" {
  statement {
    sid    = "AllowAccessToWriteToS3"
    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]
    resources = [
      aws_s3_bucket.smoketest_sms_bucket.arn,
      "${aws_s3_bucket.smoketest_sms_bucket.arn}/*",
    ]
  }
}
moved {
  from = data.aws_iam_policy_document.s3_smoketest_policy_document[0]
  to   = data.aws_iam_policy_document.s3_smoketest_policy_document
}

resource "aws_iam_role_policy_attachment" "notification_lambda_smoketest_s3" {
  role       = aws_iam_role.email_lambda_iam_role.name
  policy_arn = aws_iam_policy.s3_smoketest_policy.arn
}
moved {
  from = aws_iam_role_policy_attachment.notification_lambda_smoketest_s3[0]
  to   = aws_iam_role_policy_attachment.notification_lambda_smoketest_s3
}
