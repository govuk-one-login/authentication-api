resource "aws_vpc" "authentication" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

data "aws_availability_zones" "available" {}

resource "aws_subnet" "authentication" {
  count             = length(data.aws_availability_zones.available.names)
  vpc_id            = aws_vpc.authentication.id
  cidr_block        = "10.0.${count.index}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
}

resource "aws_route_table_association" "private" {
  count          = length(data.aws_availability_zones.available.names)
  subnet_id      = element(aws_subnet.authentication.*.id,count.index)
  route_table_id = aws_vpc.authentication.default_route_table_id
}

data "aws_vpc_endpoint_service" "sqs" {
  service = "sqs"
}

resource "aws_vpc_endpoint" "sqs" {
  vpc_endpoint_type = "Interface"
  vpc_id            = aws_vpc.authentication.id
  service_name      = data.aws_vpc_endpoint_service.sqs.service_name

  subnet_ids = [
    aws_subnet.authentication.*.id
  ]

  security_group_ids = [
    aws_vpc.authentication.default_security_group_id
  ]

  private_dns_enabled = true
}
