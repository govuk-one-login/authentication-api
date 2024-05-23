output "lambda_zip_file_source_path" {
  value = var.lambda_zip_file_path
}

output "lambda_zip_file_md5" {
  value = local.lambda_zip_file_md5
}

output "source_commit_sha" {
  value = local.source_commit_sha
}

output "object_bucket" {
  value = aws_s3_object.release_zip.bucket
}
output "object_key" {
  value = aws_s3_object.release_zip.key
}
output "object_version_id" {
  value = aws_s3_object.release_zip.version_id
}
