resource "aws_s3_bucket" "source_bucket" {
  bucket_prefix = "${var.environment}-test-services-lam-src"
}

resource "aws_s3_bucket_versioning" "source_bucket_versioning" {
  bucket = aws_s3_bucket.source_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "test_services_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "utils-release.zip"

  server_side_encryption = "AES256"
  source                 = var.test_services-api-lambda_zip_file
  source_hash            = filemd5(var.test_services-api-lambda_zip_file)
}
