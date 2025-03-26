resource "aws_security_group" "redis_security_group" {
  name_prefix = "${var.environment}-redis-security-group-"
  description = "Allow ingress to Redis. Use on Elasticache clusters only"
  vpc_id      = local.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "allow_incoming_redis_from_private_subnet" {
  description       = "Allow ingress to Redis from private subnet"
  security_group_id = aws_security_group.redis_security_group.id

  from_port   = local.redis_port_number
  protocol    = "tcp"
  cidr_blocks = local.private_subnet_cidr_blocks
  to_port     = local.redis_port_number
  type        = "ingress"
}

resource "aws_security_group_rule" "allow_incoming_redis_from_protected_subnet" {
  description       = "Allow ingress to Redis from protected subnet"
  security_group_id = aws_security_group.redis_security_group.id

  from_port   = local.redis_port_number
  protocol    = "tcp"
  cidr_blocks = local.protected_subnet_cidr_blocks
  to_port     = local.redis_port_number
  type        = "ingress"
}

resource "aws_security_group" "allow_access_to_oidc_redis" {
  name_prefix = "${var.environment}-allow-access-to-oidc-redis-"
  description = "Allow outgoing access to the OIDC Redis session store"
  vpc_id      = local.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "allow_connection_to_oidc_redis" {
  security_group_id = aws_security_group.allow_access_to_oidc_redis.id

  from_port                = local.redis_port_number
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.redis_security_group.id
  to_port                  = local.redis_port_number
  type                     = "egress"
}

resource "aws_security_group_rule" "allow_incoming_redis_from_orch_private_subnet" {
  count = length(var.orch_privatesub_cidr_blocks) == 0 ? 0 : 1

  description       = "Allow ingress to Redis from orch private subnet"
  security_group_id = aws_security_group.redis_security_group.id

  from_port   = local.redis_port_number
  protocol    = "tcp"
  cidr_blocks = var.orch_privatesub_cidr_blocks
  to_port     = local.redis_port_number
  type        = "ingress"
}

resource "aws_security_group_rule" "allow_incoming_redis_from_orch_protected_subnet" {
  count = length(var.orch_protectedsub_cidr_blocks) == 0 ? 0 : 1

  description       = "Allow ingress to Redis from orch protected subnet"
  security_group_id = aws_security_group.redis_security_group.id

  from_port   = local.redis_port_number
  protocol    = "tcp"
  cidr_blocks = var.orch_protectedsub_cidr_blocks
  to_port     = local.redis_port_number
  type        = "ingress"
}

resource "aws_security_group_rule" "allow_incoming_session_redis_from_new_auth" {
  count = length(var.new_auth_protectedsub_cidr_blocks) == 0 ? 0 : 1

  description       = "Allow ingress to Redis from new Auth equivalent environment protected subnets"
  security_group_id = aws_security_group.redis_security_group.id

  from_port   = local.redis_port_number
  protocol    = "tcp"
  cidr_blocks = var.new_auth_protectedsub_cidr_blocks
  to_port     = local.redis_port_number
  type        = "ingress"
}

# Frontend Redis security group

resource "aws_security_group" "frontend_redis_security_group" {
  name_prefix = "${var.environment}-frontend-redis-security-group-"
  description = "Allow ingress to frontend Redis. Use on Elasticache cluster only"
  vpc_id      = local.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "allow_incoming_frontend_redis_from_private_subnet" {
  security_group_id = aws_security_group.frontend_redis_security_group.id

  from_port   = local.redis_port_number
  protocol    = "tcp"
  cidr_blocks = local.private_subnet_cidr_blocks
  to_port     = local.redis_port_number
  type        = "ingress"
}

resource "aws_security_group_rule" "allow_incoming_frontend_redis_from_new_auth" {
  count = length(var.new_auth_protectedsub_cidr_blocks) == 0 ? 0 : 1

  description       = "Allow ingress to Redis from new Auth equivalent environment protected subnets"
  security_group_id = aws_security_group.frontend_redis_security_group.id

  from_port   = local.redis_port_number
  protocol    = "tcp"
  cidr_blocks = var.new_auth_protectedsub_cidr_blocks
  to_port     = local.redis_port_number
  type        = "ingress"
}

resource "aws_security_group" "allow_access_to_frontend_redis" {
  name_prefix = "${var.environment}-allow-access-to-frontend-redis-"
  description = "Allow outgoing access to the frontend Redis session store"
  vpc_id      = local.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "allow_connection_to_frontend_redis" {
  security_group_id = aws_security_group.allow_access_to_frontend_redis.id

  from_port                = local.redis_port_number
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.frontend_redis_security_group.id
  to_port                  = local.redis_port_number
  type                     = "egress"
}
