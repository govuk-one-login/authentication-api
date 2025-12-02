resource "aws_s3_bucket" "auth_ext_source_bucket" {
  bucket_prefix = "${var.environment}-auth-ext-lambda-source-"
}

resource "aws_s3_bucket_versioning" "auth_ext_source_bucket_versioning" {
  bucket = aws_s3_bucket.auth_ext_source_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "auth_ext_source_bucket_ssl_requests_only" {
  bucket = aws_s3_bucket.auth_ext_source_bucket.id

  policy = jsonencode({
    Statement = [
      {
        Sid       = "AllowSSLRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.auth_ext_source_bucket.arn,
          "${aws_s3_bucket.auth_ext_source_bucket.arn}/*"
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

resource "aws_s3_object" "auth_ext_api_release_zip" {
  bucket = aws_s3_bucket.auth_ext_source_bucket.bucket
  key    = "auth-ext-api-release.zip"

  server_side_encryption = "aws:kms"
  source                 = var.auth_ext_lambda_zip_file
  source_hash            = filemd5(var.auth_ext_lambda_zip_file)
}
