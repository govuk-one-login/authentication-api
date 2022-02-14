resource "aws_s3_bucket" "source_bucket" {
  bucket_prefix = "${var.environment}-acct-mgmt-lambda-source-"

  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket_object" "account_management_api_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "account-management-api-release.zip"

  server_side_encryption = "AES256"
  source                 = var.lambda_zip_file
  source_hash            = filemd5(var.lambda_zip_file)
}


resource "aws_s3_bucket_object" "warmer_release_zip" {
  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "warmer-release.zip"

  server_side_encryption = "AES256"
  source                 = var.lambda_warmer_zip_file
  source_hash            = filemd5(var.lambda_warmer_zip_file)
}
