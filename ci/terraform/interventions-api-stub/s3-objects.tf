resource "aws_s3_bucket" "interventions_api_stub_source_bucket" {
  bucket_prefix = "${var.environment}-int-api-stub-source-"
}

resource "aws_s3_bucket_versioning" "interventions_api_stub_source_bucket_versioning" {
  bucket = aws_s3_bucket.interventions_api_stub_source_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "interventions_api_stub_release_zip" {
  bucket = aws_s3_bucket.interventions_api_stub_source_bucket.bucket
  key    = "interventions-api-stub-release.zip"

  server_side_encryption = "AES256"
  source                 = var.interventions_api_stub_release_zip_file
  source_hash            = filemd5(var.interventions_api_stub_release_zip_file)
}
