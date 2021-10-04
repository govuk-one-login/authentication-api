resource "aws_vpc" "account_management_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.default_tags, {
    Name = "${var.environment}-account-management-vpc"
  })
}

data "aws_availability_zones" "available" {}

resource "aws_subnet" "account_management_subnets" {
  count             = length(data.aws_availability_zones.available.names)
  vpc_id            = aws_vpc.account_management_vpc.id
  cidr_block        = "10.0.${count.index}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  depends_on = [
    aws_vpc.account_management_vpc,
  ]

  tags = merge(local.default_tags, {
    Name = "${var.environment}-account-management-private-subnet-for-${data.aws_availability_zones.available.names[count.index]}"
  })
}

data "aws_vpc_endpoint_service" "sqs" {
  count   = var.use_localstack ? 0 : 1
  service = "sqs"
}

resource "aws_vpc_endpoint" "sqs" {
  count = var.use_localstack ? 0 : 1

  vpc_endpoint_type = "Interface"
  vpc_id            = aws_vpc.account_management_vpc.id
  service_name      = data.aws_vpc_endpoint_service.sqs[0].service_name

  subnet_ids = aws_subnet.account_management_subnets.*.id

  security_group_ids = [
    aws_vpc.account_management_vpc.default_security_group_id
  ]

  private_dns_enabled = true

  tags = local.default_tags

  depends_on = [
    aws_vpc.account_management_vpc,
    aws_subnet.account_management_subnets,
  ]
}

data "aws_vpc_endpoint_service" "dynamodb" {
  count   = var.use_localstack ? 0 : 1
  service = "dynamodb"
}

resource "aws_vpc_endpoint" "dynamodb" {
  count = var.use_localstack ? 0 : 1

  vpc_endpoint_type = "Gateway"
  vpc_id            = aws_vpc.account_management_vpc.id
  service_name      = data.aws_vpc_endpoint_service.dynamodb[0].service_name

  tags = local.default_tags
}

resource "aws_vpc_endpoint_route_table_association" "dynamodb" {
  vpc_endpoint_id = aws_vpc_endpoint.dynamodb[0].id
  count           = var.use_localstack ? 0 : length(data.aws_availability_zones.available.names)

  route_table_id = aws_route_table.private_route_table[count.index].id
}

resource "aws_subnet" "account_management_public" {
  count             = var.use_localstack ? 0 : length(data.aws_availability_zones.available.names)
  vpc_id            = aws_vpc.account_management_vpc.id
  cidr_block        = "10.0.${count.index + 128}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.default_tags, {
    Name = "${var.environment}-account-management-public-subnet-for-${data.aws_availability_zones.available.names[count.index]}"
  })
}

resource "aws_internet_gateway" "igw" {
  count  = var.use_localstack ? 0 : 1
  vpc_id = aws_vpc.account_management_vpc.id

  tags = merge(local.default_tags, {
    Name = "${var.environment}-account-management-internet-gateway-for-${aws_vpc.account_management_vpc.id}"
  })
}

resource "aws_eip" "nat_gateway_eip" {
  count = var.use_localstack ? 0 : length(data.aws_availability_zones.available.names)
  vpc   = true

  tags = merge(local.default_tags, {
    Name = "${var.environment}-account-management-nat-gateway-ip-for-${data.aws_availability_zones.available.names[count.index]}"
  })
}

resource "aws_nat_gateway" "nat_gateway" {
  count = var.use_localstack ? 0 : length(data.aws_availability_zones.available.names)

  allocation_id = aws_eip.nat_gateway_eip[count.index].id
  subnet_id     = aws_subnet.account_management_public[count.index].id

  tags = merge(local.default_tags, {
    Name = "${var.environment}-account-management-nat-gateway-for-${data.aws_availability_zones.available.names[count.index]}"
  })
}

resource "aws_route_table" "public_route_table" {
  count  = var.use_localstack ? 0 : 1
  vpc_id = aws_vpc.account_management_vpc.id

  tags = merge(local.default_tags, {
    Name = "${var.environment}-account-management-public-route-table-for-${aws_vpc.account_management_vpc.id}"
  })
}

resource "aws_route" "public_to_internet" {
  count                  = var.use_localstack ? 0 : 1
  route_table_id         = aws_route_table.public_route_table[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw[0].id
}

resource "aws_route_table_association" "public_to_internet" {
  count = var.use_localstack ? 0 : length(data.aws_availability_zones.available.names)

  route_table_id = aws_route_table.public_route_table[0].id
  subnet_id      = aws_subnet.account_management_public[count.index].id
}

resource "aws_route_table" "private_route_table" {
  count = var.use_localstack ? 0 : length(data.aws_availability_zones.available.names)

  vpc_id = aws_vpc.account_management_vpc.id

  tags = merge(local.default_tags, {
    Name = "${var.environment}-account-management-private-route-table-for-${data.aws_availability_zones.available.names[count.index]}"
  })
}

resource "aws_route_table_association" "private" {
  count = var.use_localstack ? 0 : length(data.aws_availability_zones.available.names)

  route_table_id = aws_route_table.private_route_table[count.index].id
  subnet_id      = aws_subnet.account_management_subnets[count.index].id
}

resource "aws_route" "private_to_internet" {
  count = var.use_localstack ? 0 : length(data.aws_availability_zones.available.names)

  route_table_id         = aws_route_table.private_route_table[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat_gateway[count.index].id

  depends_on = [
    aws_route_table.private_route_table,
    aws_route_table_association.private,
  ]
}
