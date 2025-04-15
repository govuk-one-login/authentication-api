
locals {
  restricted_environments = ["production", "integration"]
  create_resource         = !contains(local.restricted_environments, var.environment)
}

resource "aws_s3_bucket" "am_api_acceptance_tests_otp_bucket" {
  count = local.create_resource ? 1 : 0
  #checkov:skip=CKV_AWS_21:Bucket used for testing only so doesn't need encryption
  #checkov:skip=CKV_AWS_21:Bucket used for testing only so doesn't need versioning
  #checkov:skip=CKV_AWS_144:Bucket used for testing only so doesn't need cross-region replication
  #checkov:skip=CKV_AWS_145:Bucket used for testing only so doesn't need encryption
  #checkov:skip=CKV_AWS_18:Bucket used for testing only so doesn't need access logging
  #checkov:skip=CKV2_AWS_61:Bucket used for testing only so doesnt need lifecycle configuration
  #checkov:skip=CKV2_AWS_62:Bucket used for testing only so doesn't need event notifications
  bucket = "${var.environment}-am-api-acceptance-tests-otp"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "am_api_acceptance_tests_otp_bucket" {
  count  = local.create_resource ? 1 : 0
  bucket = aws_s3_bucket.am_api_acceptance_tests_otp_bucket[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "am_api_acceptance_tests_otp_bucket" {
  count  = local.create_resource ? 1 : 0
  bucket = aws_s3_bucket.am_api_acceptance_tests_otp_bucket[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }

}

resource "aws_s3_bucket_public_access_block" "am_api_acceptance_tests_otp_private_bucket" {
  count                   = local.create_resource ? 1 : 0
  bucket                  = aws_s3_bucket.am_api_acceptance_tests_otp_bucket[0].id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_iam_policy" "am_api_acceptance_tests_otp_bucket_policy" {
  count       = local.create_resource ? 1 : 0
  name        = "${var.environment}-s3-am_api_acceptance_tests_otp_bucket-policy"
  path        = "/"
  description = "IAM policy for managing S3 connection to the S3 Acceptance Tests bucket"

  policy = data.aws_iam_policy_document.s3_am_api_acceptance_tests_otp_bucket_policy_document[0].json
}


data "aws_iam_policy_document" "s3_am_api_acceptance_tests_otp_bucket_policy_document" {
  count = local.create_resource ? 1 : 0
  statement {
    sid    = "AllowAccessToWriteToS3"
    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]
    resources = [
      aws_s3_bucket.am_api_acceptance_tests_otp_bucket[0].arn,
      "${aws_s3_bucket.am_api_acceptance_tests_otp_bucket[0].arn}/*",
    ]
  }
}


resource "aws_iam_role_policy_attachment" "notification_lambda_smoketest_s3" {
  count      = local.create_resource ? 1 : 0
  role       = module.account_management_api_send_notification_role.name
  policy_arn = aws_iam_policy.am_api_acceptance_tests_otp_bucket_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "notification_sqs_lambda_s3" {
  count      = local.create_resource ? 1 : 0
  role       = module.account_management_sqs_role.name
  policy_arn = aws_iam_policy.am_api_acceptance_tests_otp_bucket_policy[0].arn
}
