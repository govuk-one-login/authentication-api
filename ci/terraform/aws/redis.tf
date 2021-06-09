resource "aws_elasticache_subnet_group" "sessions_store" {
  name       = "${var.environment}-session-store-cache-subnet"
  subnet_ids = aws_subnet.authentication.*.id
}

resource "aws_elasticache_replication_group" "sessions_store" {
  automatic_failover_enabled    = true
  availability_zones            = data.aws_availability_zones.available.names
  replication_group_id          = "${var.environment}-sessions-store"
  replication_group_description = "A Redis cluster for storing user session data"
  node_type                     = "cache.t2.micro"
  number_cache_clusters         = length(data.aws_availability_zones.available.names)
  engine                        = "redis"
  engine_version                = "6.0.5"
  parameter_group_name          = "default.redis6.x"
  port                          = 6379

  subnet_group_name    = aws_elasticache_subnet_group.sessions_store.name
  security_group_ids   = [aws_security_group.elasticache_security_group.id]
}