locals {
  redis_port_number = 6379
}

resource "aws_elasticache_subnet_group" "account_management_redis_session_store" {
  name       = "${var.environment}-acct-mgmt-redis-session-store-cache-subnet"
  subnet_ids = local.private_subnet_ids

  tags = local.default_tags
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
  replication_group_id          = "${var.environment}-acct-mgmt-session-store"
  replication_group_description = "A Redis cluster for storing user session data"
  node_type                     = var.redis_node_size
  number_cache_clusters         = length(data.aws_availability_zones.available.names)
  engine                        = "redis"
  engine_version                = "6.x"
  parameter_group_name          = "default.redis6.x"
  port                          = local.redis_port_number
  maintenance_window            = "mon:02:00-mon:03:00"
  notification_topic_arn        = data.aws_sns_topic.slack_events.arn

  multi_az_enabled = true

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_password.result
  apply_immediately          = true

  subnet_group_name = aws_elasticache_subnet_group.account_management_redis_session_store.name
  security_group_ids = [
    aws_security_group.am_redis_security_group.id
  ]

  lifecycle {
    ignore_changes = [
      engine_version
    ]
  }

  tags = local.default_tags
}