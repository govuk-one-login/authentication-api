resource "aws_elasticache_subnet_group" "account_management_sessions_store" {
  count = var.use_localstack ? 0 : 1

  name       = "${var.environment}-session-store-cache-subnet"
  subnet_ids = aws_subnet.account_management_subnets.*.id
  depends_on = [
    aws_vpc.account_management_vpc,
    aws_subnet.account_management_subnets,
  ]
}

resource "random_password" "redis_password" {
  length = 32

  override_special = "!&#$^<>-"
  min_lower        = 3
  min_numeric      = 3
  min_special      = 3
  min_upper        = 3
}

resource "aws_elasticache_replication_group" "account_management_sessions_store" {
  count = var.use_localstack ? 0 : 1

  automatic_failover_enabled    = true
  availability_zones            = data.aws_availability_zones.available.names
  replication_group_id          = "${var.environment}-sessions-store"
  replication_group_description = "A Redis cluster for storing user session data"
  node_type                     = "cache.t2.medium"
  number_cache_clusters         = length(data.aws_availability_zones.available.names)
  engine                        = "redis"
  engine_version                = "6.x"
  parameter_group_name          = "default.redis6.x"
  port                          = 6379

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_password.result
  apply_immediately          = true

  subnet_group_name  = aws_elasticache_subnet_group.account_management_sessions_store[0].name
  security_group_ids = [aws_vpc.account_management_vpc.default_security_group_id]

  lifecycle {
    ignore_changes = [
      engine_version
    ]
  }

  tags = local.default_tags

  depends_on = [
    aws_vpc.account_management_vpc,
    aws_subnet.account_management_subnets,
  ]
}