resource "aws_s3_bucket" "ticf_cri_stub_source_bucket" {
  bucket_prefix = "${var.environment}-ticf-cri-stub-source-"
}

resource "aws_s3_bucket_versioning" "ticf_cri_stub_source_bucket_versioning" {
  bucket = aws_s3_bucket.ticf_cri_stub_source_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "ticf_cri_bucket_ssl_requests_only" {
  bucket = aws_s3_bucket.ticf_cri_stub_source_bucket.id

  policy = jsonencode({
    Statement = [
      {
        Sid       = "AllowSSLRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.ticf_cri_stub_source_bucket.arn,
          "${aws_s3_bucket.ticf_cri_stub_source_bucket.arn}/*"
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

resource "aws_s3_object" "ticf_cri_stub_release_zip" {
  bucket = aws_s3_bucket.ticf_cri_stub_source_bucket.bucket
  key    = "ticf-cri-stub-release.zip"

  server_side_encryption = "aws:kms"
  source                 = var.ticf_cri_stub_release_zip_file
  source_hash            = filemd5(var.ticf_cri_stub_release_zip_file)
}
