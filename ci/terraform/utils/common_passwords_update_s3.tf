resource "aws_s3_bucket" "common_passwords" {
  bucket = "${var.environment}-common-passwords-bucket"
}

resource "aws_s3_bucket_public_access_block" "common_passwords_private_bucket" {
  bucket                  = aws_s3_bucket.common_passwords.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "common_passwords_bucket_ssl_requests_only" {
  bucket = aws_s3_bucket.common_passwords.id

  policy = jsonencode({
    Statement = [
      {
        Sid       = "AllowSSLRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.common_passwords.arn,
          "${aws_s3_bucket.common_passwords.arn}/*"
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

resource "aws_s3_bucket_acl" "common_passwords" {
  bucket = aws_s3_bucket.common_passwords.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "common_passwords" {
  bucket = aws_s3_bucket.common_passwords.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "common_passwords" {
  bucket = aws_s3_bucket.common_passwords.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_iam_policy" "common_passwords_s3_read_access" {
  name_prefix = "lambda-s3-access"
  path        = "/"
  description = "IAM policy for managing s3 access for common passwords DynamoDB update lambda"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket",
      ]

      Resource = [aws_s3_bucket.common_passwords.arn, "${aws_s3_bucket.common_passwords.arn}/*"]
    }]
  })
}
