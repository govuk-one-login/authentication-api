resource "aws_lambda_layer_version" "lambda_layer" {
  filename         = var.zip_file_path
  source_code_hash = filebase64sha256(var.zip_file_path)

  layer_name = "${var.environment}-${var.layer_name}"

  skip_destroy = true
}
