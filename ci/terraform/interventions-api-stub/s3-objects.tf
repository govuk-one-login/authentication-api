resource "aws_s3_bucket" "interventions_api_stub_source_bucket" {
  bucket_prefix = "${var.environment}-int-api-stub-source-"
}

resource "aws_s3_bucket_versioning" "interventions_api_stub_source_bucket_versioning" {
  bucket = aws_s3_bucket.interventions_api_stub_source_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "interventions_api_stub_source_bucket_encryption" {
  bucket = aws_s3_bucket.interventions_api_stub_source_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "alias/aws/s3"
    }
  }
}

resource "aws_s3_bucket_policy" "interventions_bucket_ssl_requests_only" {
  bucket = aws_s3_bucket.interventions_api_stub_source_bucket.id

  policy = jsonencode({
    Statement = [
      {
        Sid       = "AllowSSLRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.interventions_api_stub_source_bucket.arn,
          "${aws_s3_bucket.interventions_api_stub_source_bucket.arn}/*"
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

resource "aws_s3_object" "interventions_api_stub_release_zip" {
  bucket = aws_s3_bucket.interventions_api_stub_source_bucket.bucket
  key    = "interventions-api-stub-release.zip"

  server_side_encryption = "aws:kms"
  source                 = var.interventions_api_stub_release_zip_file
  source_hash            = filemd5(var.interventions_api_stub_release_zip_file)
}
