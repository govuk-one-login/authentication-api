resource "aws_s3_bucket" "smoketest_sms_bucket" {
  bucket = "${var.environment}-smoke-test-sms-codes"

  acl = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = local.default_tags
}
