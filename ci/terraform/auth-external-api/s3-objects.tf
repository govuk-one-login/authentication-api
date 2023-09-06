resource "aws_s3_bucket" "auth_ext_source_bucket" {
  bucket_prefix = "${var.environment}-auth-ext-lambda-source-"
}

resource "aws_s3_bucket_versioning" "auth_ext_source_bucket_versioning" {
  bucket = aws_s3_bucket.auth_ext_source_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "auth_ext_api_release_zip" {
  bucket = aws_s3_bucket.auth_ext_source_bucket.bucket
  key    = "auth-ext-api-release.zip"

  server_side_encryption = "AES256"
  source                 = var.auth_ext_lambda_zip_file
  source_hash            = filemd5(var.auth_ext_lambda_zip_file)
}
