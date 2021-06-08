resource "aws_elasticache_cluster" "sessions_store" {
  cluster_id           = "sessions-store"
  engine               = "redis"
  node_type            = "cache.t2.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis6.x"
  engine_version       = "6.x"
  port                 = 6379
  security_group_ids = [
    aws_security_group.elasticache_security_group.id
  ]
}