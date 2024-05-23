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

module "account_management_api_release_object" {
  source = "../modules/lambda_release_zip"

  lambda_zip_file_path = var.lambda_zip_file
  java_module_name     = "account-management-api"

  bucket = aws_s3_bucket.source_bucket.bucket
  key    = "account-management-api-release.zip"
}

moved {
  from = aws_s3_object.account_management_api_release_zip
  to   = module.account_management_api_release_object.aws_s3_object.release_zip
}
