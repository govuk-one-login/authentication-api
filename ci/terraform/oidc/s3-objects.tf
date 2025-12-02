resource "aws_s3_bucket" "source_bucket" {
  bucket_prefix = "${var.environment}-lambda-source-"
}

resource "aws_s3_bucket_versioning" "source_bucket_versioning" {
  bucket = aws_s3_bucket.source_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "private_source_bucket" {
  bucket                  = aws_s3_bucket.source_bucket.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
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

resource "aws_s3_object" "oidc_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "oidc-api-release.zip"

  server_side_encryption = "aws:kms"
  source                 = var.oidc_api_lambda_zip_file
  source_hash            = filemd5(var.oidc_api_lambda_zip_file)
}

resource "aws_s3_object" "client_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "client-api-release.zip"

  server_side_encryption = "aws:kms"
  source                 = var.client_registry_api_lambda_zip_file
  source_hash            = filemd5(var.client_registry_api_lambda_zip_file)
}

resource "aws_s3_object" "frontend_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "frontend-api-release.zip"

  server_side_encryption = "aws:kms"
  source                 = var.frontend_api_lambda_zip_file
  source_hash            = filemd5(var.frontend_api_lambda_zip_file)
}

resource "aws_s3_object" "ipv_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "ipv-api-release.zip"

  server_side_encryption = "aws:kms"
  source                 = var.ipv_api_lambda_zip_file
  source_hash            = filemd5(var.ipv_api_lambda_zip_file)
}

resource "aws_s3_object" "doc_checking_app_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "doc-checking-app-api-release.zip"

  server_side_encryption = "aws:kms"
  source                 = var.doc_checking_app_api_lambda_zip_file
  source_hash            = filemd5(var.doc_checking_app_api_lambda_zip_file)
}
