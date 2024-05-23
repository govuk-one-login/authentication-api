locals {
  lambda_zip_file_md5 = filemd5(var.lambda_zip_file_path)
}

resource "aws_s3_object" "release_zip" {
  bucket = var.bucket
  key    = var.key

  server_side_encryption = var.server_side_encryption
  source                 = var.lambda_zip_file_path
  source_hash            = local.lambda_zip_file_md5
}
