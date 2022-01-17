#!/usr/bin/env bash

STATE_OUT="../../../../di-infrastructure/terraform/core/core.tfstate"
STATE_IN="api.tfstate"

function migrate() {
  terraform state mv -state "${STATE_IN}" -state-out "${STATE_OUT}" "$1" "$2"
}

migrate aws_vpc.authentication aws_vpc.authentication

migrate aws_subnet.authentication[0] aws_subnet.authentication_private[0]
migrate aws_subnet.authentication[1] aws_subnet.authentication_private[1]
migrate aws_subnet.authentication[2] aws_subnet.authentication_private[2]

migrate aws_security_group.aws_endpoints aws_security_group.aws_endpoints
migrate aws_security_group_rule.allow_incoming_aws_https_requests_from_private_subnet aws_security_group_rule.allow_incoming_aws_https_requests_from_private_subnet

migrate data.aws_vpc_endpoint_service.sqs[0] data.aws_vpc_endpoint_service.sqs
migrate aws_vpc_endpoint.sqs[0] aws_vpc_endpoint.sqs

migrate data.aws_vpc_endpoint_service.dynamodb[0] data.aws_vpc_endpoint_service.dynamodb
migrate aws_vpc_endpoint.dynamodb[0] aws_vpc_endpoint.dynamodb
migrate aws_vpc_endpoint_route_table_association.dynamodb[0] aws_vpc_endpoint_route_table_association.dynamodb[0]
migrate aws_vpc_endpoint_route_table_association.dynamodb[1] aws_vpc_endpoint_route_table_association.dynamodb[1]
migrate aws_vpc_endpoint_route_table_association.dynamodb[2] aws_vpc_endpoint_route_table_association.dynamodb[2]

migrate data.aws_vpc_endpoint_service.sns[0] data.aws_vpc_endpoint_service.sns
migrate aws_vpc_endpoint.sns[0] aws_vpc_endpoint.sns

migrate data.aws_vpc_endpoint_service.kms[0] data.aws_vpc_endpoint_service.kms
migrate aws_vpc_endpoint.kms[0] aws_vpc_endpoint.kms

migrate data.aws_vpc_endpoint_service.ssm[0] data.aws_vpc_endpoint_service.ssm
migrate aws_vpc_endpoint.ssm[0] aws_vpc_endpoint.ssm

migrate data.aws_vpc_endpoint_service.s3[0] data.aws_vpc_endpoint_service.s3
migrate aws_vpc_endpoint.s3[0] aws_vpc_endpoint.s3
migrate aws_vpc_endpoint_route_table_association.s3[0] aws_vpc_endpoint_route_table_association.s3[0]
migrate aws_vpc_endpoint_route_table_association.s3[1] aws_vpc_endpoint_route_table_association.s3[1]
migrate aws_vpc_endpoint_route_table_association.s3[2] aws_vpc_endpoint_route_table_association.s3[2]

migrate data.aws_vpc_endpoint_service.lambda[0] data.aws_vpc_endpoint_service.lambda
migrate aws_vpc_endpoint.lambda[0] aws_vpc_endpoint.lambda

migrate aws_subnet.authentication_public[0] aws_subnet.authentication_public[0]
migrate aws_subnet.authentication_public[1] aws_subnet.authentication_public[1]
migrate aws_subnet.authentication_public[2] aws_subnet.authentication_public[2]

migrate aws_internet_gateway.igw[0] aws_internet_gateway.igw

migrate aws_eip.nat_gateway_eip[0] aws_eip.nat_gateway_eip[0]
migrate aws_eip.nat_gateway_eip[1] aws_eip.nat_gateway_eip[1]
migrate aws_eip.nat_gateway_eip[2] aws_eip.nat_gateway_eip[2]

migrate aws_nat_gateway.nat_gateway[0] aws_nat_gateway.nat_gateway[0]
migrate aws_nat_gateway.nat_gateway[1] aws_nat_gateway.nat_gateway[1]
migrate aws_nat_gateway.nat_gateway[2] aws_nat_gateway.nat_gateway[2]

migrate aws_route_table.public_route_table[0] aws_route_table.public_route_table
migrate aws_route.public_to_internet[0] aws_route.public_to_internet
migrate aws_route_table_association.public_to_internet[0] aws_route_table_association.public_to_internet[0]
migrate aws_route_table_association.public_to_internet[1] aws_route_table_association.public_to_internet[1]
migrate aws_route_table_association.public_to_internet[2] aws_route_table_association.public_to_internet[2]

migrate aws_route_table.private_route_table[0] aws_route_table.private_route_table[0]
migrate aws_route_table.private_route_table[1] aws_route_table.private_route_table[1]
migrate aws_route_table.private_route_table[2] aws_route_table.private_route_table[2]

migrate aws_route_table_association.private[0] aws_route_table_association.private[0]
migrate aws_route_table_association.private[1] aws_route_table_association.private[1]
migrate aws_route_table_association.private[2] aws_route_table_association.private[2]

migrate aws_route.private_to_internet[0] aws_route.private_to_internet[0]
migrate aws_route.private_to_internet[1] aws_route.private_to_internet[1]
migrate aws_route.private_to_internet[2] aws_route.private_to_internet[2]

migrate aws_security_group.allow_vpc_resources_only aws_security_group.allow_aws_service_access
migrate aws_security_group.allow_egress aws_security_group.allow_egress

migrate aws_security_group_rule.allow_https_to_aws_services aws_security_group_rule.allow_https_to_aws_services
migrate aws_security_group_rule.allow_https_to_dynamo aws_security_group_rule.allow_https_to_dynamo
migrate aws_security_group_rule.allow_https_to_s3 aws_security_group_rule.allow_https_to_s3
migrate aws_security_group_rule.allow_https_to_anywhere aws_security_group_rule.allow_https_to_anywhere
