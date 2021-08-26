resource "aws_ecr_repository" "authentication" {
  count = var.use_localstack ? 0 : 1

  name                 = "${var.environment}-authentication"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.default_tags
}