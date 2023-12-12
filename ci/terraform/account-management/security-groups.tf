resource "aws_security_group" "am_redis_security_group" {
  name_prefix = "${var.environment}-redis-security-group-"
  description = "Allow ingress to AM session Redis. Use on Elasticache cluster only"
  vpc_id      = local.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "allow_incoming_am_redis_from_private_subnet" {
  security_group_id = aws_security_group.am_redis_security_group.id

  from_port   = local.redis_port_number
  protocol    = "tcp"
  cidr_blocks = local.private_subnet_cidr_blocks
  to_port     = local.redis_port_number
  type        = "ingress"
}

resource "aws_security_group" "allow_access_to_am_redis" {
  name_prefix = "${var.environment}-allow-access-to-acct-mgmt-redis-"
  description = "Allow outgoing access to the Account Management API Redis session store"
  vpc_id      = local.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "allow_connection_to_am_redis" {
  security_group_id = aws_security_group.allow_access_to_am_redis.id

  from_port                = local.redis_port_number
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.am_redis_security_group.id
  to_port                  = local.redis_port_number
  type                     = "egress"
}
