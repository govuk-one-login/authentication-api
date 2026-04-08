resource "aws_s3_bucket" "bulk_test_user" {
  bucket = "${var.environment}-bulk-test-user-bucket"
}

resource "aws_s3_bucket_public_access_block" "bulk_test_private_bucket" {
  bucket                  = aws_s3_bucket.bulk_test_user.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "bulk_test_user" {
  bucket = aws_s3_bucket.bulk_test_user.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "bulk_test_user" {
  bucket = aws_s3_bucket.bulk_test_user.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "bulk_test_user_bucket_ssl_requests_only" {
  bucket = aws_s3_bucket.bulk_test_user.id

  policy = jsonencode({
    Statement = [
      {
        Sid       = "AllowSSLRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.bulk_test_user.arn,
          "${aws_s3_bucket.bulk_test_user.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bulk_test_user" {
  bucket = aws_s3_bucket.bulk_test_user.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "alias/aws/s3"
    }
  }
}

resource "aws_iam_policy" "bulk_test_user_s3_read_access" {
  name_prefix = "lambda-s3-access"
  path        = "/"
  description = "IAM policy for managing s3 access for bulk test user create lambda"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket",
      ]

      Resource = [aws_s3_bucket.bulk_test_user.arn, "${aws_s3_bucket.bulk_test_user.arn}/*"]
    }]
  })
}
