resource "aws_s3_bucket" "ticf_cri_stub_source_bucket" {
  bucket_prefix = "${var.environment}-ticf-cri-stub-source-"
}

resource "aws_s3_bucket_versioning" "ticf_cri_stub_source_bucket_versioning" {
  bucket = aws_s3_bucket.ticf_cri_stub_source_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "ticf_cri_stub_release_zip" {
  bucket = aws_s3_bucket.ticf_cri_stub_source_bucket.bucket
  key    = "ticf-cri-stub-release.zip"

  server_side_encryption = "AES256"
  source                 = var.ticf_cri_stub_release_zip_file
  source_hash            = filemd5(var.ticf_cri_stub_release_zip_file)
}
