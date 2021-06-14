resource "aws_elasticache_subnet_group" "sessions_store" {
  name       = "${var.environment}-session-store-cache-subnet"
  subnet_ids = aws_subnet.authentication.*.id
}

resource "random_password" "redis_password" {
  length = 32
}

resource "aws_elasticache_replication_group" "sessions_store" {
  automatic_failover_enabled    = true
  availability_zones            = data.aws_availability_zones.available.names
  replication_group_id          = "${var.environment}-sessions-store"
  replication_group_description = "A Redis cluster for storing user session data"
  node_type                     = "cache.t2.micro"
  number_cache_clusters         = length(data.aws_availability_zones.available.names)
  engine                        = "redis"
  engine_version                = "6.x"
  parameter_group_name          = "default.redis6.x"
  port                          = 6379

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_password.result
  apply_immediately          = true

  subnet_group_name    = aws_elasticache_subnet_group.sessions_store.name
  security_group_ids   = [aws_vpc.authentication.default_security_group_id]

  lifecycle {
    ignore_changes = [
      engine_version
    ]
  }
}