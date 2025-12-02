resource "aws_s3_bucket" "source_bucket" {
  bucket_prefix = "${var.environment}-acct-mgmt-lambda-source-"
}

resource "aws_s3_bucket_public_access_block" "source_private_bucket" {
  bucket                  = aws_s3_bucket.source_bucket.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "source_bucket_versioning" {
  bucket = aws_s3_bucket.source_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "source_bucket_ssl_requests_only" {
  bucket = aws_s3_bucket.source_bucket.id

  policy = jsonencode({
    Statement = [
      {
        Sid       = "AllowSSLRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.source_bucket.arn,
          "${aws_s3_bucket.source_bucket.arn}/*"
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

resource "aws_s3_object" "account_management_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "account-management-api-release.zip"

  server_side_encryption = "aws:kms"
  source                 = var.lambda_zip_file
  source_hash            = filemd5(var.lambda_zip_file)
}
