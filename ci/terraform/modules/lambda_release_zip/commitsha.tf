locals {
  source_zip_directory = dirname(var.lambda_zip_file_path)
  commit_sha_file_path = "${local.source_zip_directory}/${var.java_module_name}_commitsha.txt"

  source_commit_sha = fileexists(local.commit_sha_file_path) ? file(local.commit_sha_file_path) : "unknown"
}
