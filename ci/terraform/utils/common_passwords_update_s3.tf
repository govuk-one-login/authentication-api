resource "aws_s3_bucket" "common_passwords" {
  bucket = "${var.environment}-common-passwords-bucket"
  tags   = local.default_tags
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
      sse_algorithm = "AES256"
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