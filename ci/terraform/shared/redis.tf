locals {
  redis_port_number = 6379
}

resource "aws_elasticache_subnet_group" "sessions_store" {
  name       = "${var.environment}-session-store-cache-subnet"
  subnet_ids = local.private_subnet_ids
}


resource "random_password" "redis_password" {
  length = 32

  override_special = "!&#$^<>-"
  min_lower        = 3
  min_numeric      = 3
  min_special      = 3
  min_upper        = 3
}

resource "aws_elasticache_replication_group" "sessions_store" {
  automatic_failover_enabled  = true
  preferred_cache_cluster_azs = data.aws_availability_zones.available.names
  replication_group_id        = "${var.environment}-sessions-store"
  description                 = "A Redis cluster for storing user session data"
  node_type                   = var.redis_node_size
  num_cache_clusters          = length(data.aws_availability_zones.available.names)
  engine                      = "redis"
  engine_version              = "6.x"
  parameter_group_name        = "default.redis6.x"
  port                        = local.redis_port_number
  multi_az_enabled            = true
  maintenance_window          = "wed:22:00-wed:23:00"
  notification_topic_arn      = aws_sns_topic.slack_events.arn

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_password.result
  apply_immediately          = true

  subnet_group_name = aws_elasticache_subnet_group.sessions_store.name
  security_group_ids = [
    aws_security_group.redis_security_group.id,
  ]

  lifecycle {
    ignore_changes = [
      engine_version
    ]
  }

  depends_on = [
    aws_sns_topic.slack_events,
  ]
}

data "aws_sns_topic" "slack_events" {
  name = "${var.environment}-slack-events"
}


resource "aws_elasticache_subnet_group" "frontend_redis_session_store" {
  name       = "${var.environment}-frontend-redis-subnet"
  subnet_ids = local.private_subnet_ids
}


resource "random_password" "frontend_redis_password" {
  length = 32

  override_special = "!&#$^<>-"
  min_lower        = 3
  min_numeric      = 3
  min_special      = 3
  min_upper        = 3
}

resource "aws_elasticache_replication_group" "frontend_sessions_store" {
  automatic_failover_enabled  = true
  preferred_cache_cluster_azs = data.aws_availability_zones.available.names
  replication_group_id        = "${var.environment}-frontend-cache"
  description                 = "A Redis cluster for storing user session data for the frontend"
  node_type                   = var.redis_node_size
  num_cache_clusters          = length(data.aws_availability_zones.available.names)
  engine                      = "redis"
  engine_version              = "6.x"
  parameter_group_name        = "default.redis6.x"
  port                        = local.redis_port_number
  maintenance_window          = "sun:22:00-sun:23:00"
  notification_topic_arn      = data.aws_sns_topic.slack_events.arn

  multi_az_enabled = true

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.frontend_redis_password.result
  apply_immediately          = true

  subnet_group_name = aws_elasticache_subnet_group.frontend_redis_session_store.name
  security_group_ids = [
    aws_security_group.frontend_redis_security_group.id
  ]

  lifecycle {
    ignore_changes = [
      engine_version, auth_token
    ]
  }
}
