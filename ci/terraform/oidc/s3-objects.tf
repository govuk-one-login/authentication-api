resource "aws_s3_bucket" "source_bucket" {
  bucket_prefix = "${var.environment}-lambda-source-"

  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket_object" "oidc_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "oidc-api-release.zip"

  server_side_encryption = "AES256"
  source                 = var.oidc_api_lambda_zip_file
  source_hash            = filemd5(var.oidc_api_lambda_zip_file)
}

resource "aws_s3_bucket_object" "client_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "client-api-release.zip"

  server_side_encryption = "AES256"
  source                 = var.client_registry_api_lambda_zip_file
  source_hash            = filemd5(var.client_registry_api_lambda_zip_file)
}

resource "aws_s3_bucket_object" "frontend_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "frontend-api-release.zip"

  server_side_encryption = "AES256"
  source                 = var.frontend_api_lambda_zip_file
  source_hash            = filemd5(var.frontend_api_lambda_zip_file)
}

resource "aws_s3_bucket_object" "warmer_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "warmer-release.zip"

  server_side_encryption = "AES256"
  source                 = var.lambda_warmer_zip_file
  source_hash            = filemd5(var.lambda_warmer_zip_file)
}

resource "aws_s3_bucket_object" "ipv_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "ipv-api-release.zip"

  server_side_encryption = "AES256"
  source                 = var.ipv_api_lambda_zip_file
  source_hash            = filemd5(var.ipv_api_lambda_zip_file)
}

resource "aws_s3_bucket_object" "doc_checking_app_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "doc-checking-app-api-release.zip"

  server_side_encryption = "AES256"
  source                 = var.doc_checking_app_api_lambda_zip_file
  source_hash            = filemd5(var.doc_checking_app_api_lambda_zip_file)
}
