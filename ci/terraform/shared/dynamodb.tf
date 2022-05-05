resource "aws_dynamodb_table" "user_credentials_table" {
  name         = "${var.environment}-user-credentials"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "Email"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  attribute {
    name = "Email"
    type = "S"
  }

  attribute {
    name = "SubjectID"
    type = "S"
  }

  global_secondary_index {
    name            = "SubjectIDIndex"
    hash_key        = "SubjectID"
    projection_type = "ALL"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  server_side_encryption {
    enabled = !var.use_localstack
  }

  point_in_time_recovery {
    enabled = !var.use_localstack
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = local.default_tags
}

resource "aws_dynamodb_table" "user_profile_table" {
  name         = "${var.environment}-user-profile"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "Email"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  attribute {
    name = "Email"
    type = "S"
  }

  attribute {
    name = "SubjectID"
    type = "S"
  }

  attribute {
    name = "PublicSubjectID"
    type = "S"
  }

  global_secondary_index {
    name            = "SubjectIDIndex"
    hash_key        = "SubjectID"
    projection_type = "ALL"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  global_secondary_index {
    name            = "PublicSubjectIDIndex"
    hash_key        = "PublicSubjectID"
    projection_type = "ALL"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  server_side_encryption {
    enabled = !var.use_localstack
  }

  point_in_time_recovery {
    enabled = !var.use_localstack
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = local.default_tags
}

resource "aws_dynamodb_table" "client_registry_table" {
  name         = "${var.environment}-client-registry"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "ClientID"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  attribute {
    name = "ClientID"
    type = "S"
  }

  attribute {
    name = "ClientName"
    type = "S"
  }

  global_secondary_index {
    name            = "ClientNameIndex"
    hash_key        = "ClientName"
    projection_type = "ALL"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  point_in_time_recovery {
    enabled = !var.use_localstack
  }

  server_side_encryption {
    enabled = !var.use_localstack
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = local.default_tags
}

resource "aws_dynamodb_table" "identity_credentials_table" {
  name         = "${var.environment}-identity-credentials"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "SubjectID"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  attribute {
    name = "SubjectID"
    type = "S"
  }

  point_in_time_recovery {
    enabled = !var.use_localstack
  }

  server_side_encryption {
    enabled = !var.use_localstack
  }

  lifecycle {
    prevent_destroy = false
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }

  tags = local.default_tags
}

resource "aws_dynamodb_table" "doc_app_credential_table" {
  name         = "${var.environment}-doc-app-credential"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "SubjectID"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  attribute {
    name = "SubjectID"
    type = "S"
  }

  point_in_time_recovery {
    enabled = !var.use_localstack
  }

  server_side_encryption {
    enabled = !var.use_localstack
  }

  lifecycle {
    prevent_destroy = false
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }

  tags = local.default_tags
}
