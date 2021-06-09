resource "aws_vpc" "authentication" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

resource "aws_security_group" "elasticache_security_group" {
  name        = "${var.environment}-elasticache-security-group"
  vpc_id      = aws_vpc.authentication.id
  description = "Security group to allow access to Redis"
}

data "aws_availability_zones" "available" {}

resource "aws_subnet" "authentication" {
  count             = length(data.aws_availability_zones.available.names)
  vpc_id            = aws_vpc.authentication.id
  cidr_block        = "10.0.${count.index}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
}