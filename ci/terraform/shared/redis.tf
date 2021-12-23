resource "aws_elasticache_subnet_group" "sessions_store" {
  count = var.use_localstack ? 0 : 1

  name       = "${var.environment}-session-store-cache-subnet"
  subnet_ids = aws_subnet.authentication.*.id
  depends_on = [
    aws_vpc.authentication,
    aws_subnet.authentication,
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

resource "aws_elasticache_replication_group" "sessions_store" {
  count = var.use_localstack ? 0 : 1

  automatic_failover_enabled    = true
  availability_zones            = data.aws_availability_zones.available.names
  replication_group_id          = "${var.environment}-sessions-store"
  replication_group_description = "A Redis cluster for storing user session data"
  node_type                     = var.redis_node_size
  number_cache_clusters         = length(data.aws_availability_zones.available.names)
  engine                        = "redis"
  engine_version                = "6.x"
  parameter_group_name          = "default.redis6.x"
  port                          = 6379
  multi_az_enabled              = true
  maintenance_window            = "thu:02:00-thu:03:00"
  notification_topic_arn        = aws_sns_topic.slack_events.arn

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_password.result
  apply_immediately          = true

  subnet_group_name  = aws_elasticache_subnet_group.sessions_store[0].name
  security_group_ids = [aws_vpc.authentication.default_security_group_id]

  lifecycle {
    ignore_changes = [
      engine_version
    ]
  }

  tags = local.default_tags

  depends_on = [
    aws_vpc.authentication,
    aws_subnet.authentication,
    aws_sns_topic.slack_events,
  ]
}