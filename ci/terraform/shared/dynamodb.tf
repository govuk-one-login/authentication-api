locals {
  deploy_unmigrated_users_index = var.environment != "production" || var.environment != "integration" ? ["1"] : []
}

resource "aws_dynamodb_table" "user_credentials_table" {
  name         = "${var.environment}-user-credentials"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "Email"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  deletion_protection_enabled = var.dynamo_deletion_protection_enabled

  attribute {
    name = "Email"
    type = "S"
  }

  attribute {
    name = "SubjectID"
    type = "S"
  }

  attribute {
    name = "testUser"
    type = "N"
  }

  dynamic "attribute" {
    for_each = local.deploy_unmigrated_users_index
    content {
      name = "MigratedPassword"
      type = "S"
    }
  }

  global_secondary_index {
    name            = "SubjectIDIndex"
    hash_key        = "SubjectID"
    projection_type = "ALL"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  global_secondary_index {
    name            = "TestUserIndex"
    hash_key        = "SubjectID"
    range_key       = "testUser"
    projection_type = "KEYS_ONLY"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  dynamic "global_secondary_index" {
    for_each = local.deploy_unmigrated_users_index
    content {
      name            = "UnmigratedGovukAccountUsers"
      hash_key        = "SubjectID"
      range_key       = "MigratedPassword"
      projection_type = "KEYS_ONLY"
      read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
      write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
    }
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_table" "user_profile_table" {
  name             = "${var.environment}-user-profile"
  billing_mode     = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key         = "Email"
  stream_enabled   = var.enable_user_profile_stream
  stream_view_type = var.enable_user_profile_stream ? "NEW_AND_OLD_IMAGES" : null

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  deletion_protection_enabled = var.dynamo_deletion_protection_enabled

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

  attribute {
    name = "accountVerified"
    type = "N"
  }

  attribute {
    name = "testUser"
    type = "N"
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

  global_secondary_index {
    name            = "VerifiedAccountIndex"
    hash_key        = "SubjectID"
    range_key       = "accountVerified"
    projection_type = "KEYS_ONLY"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  global_secondary_index {
    name            = "TestUserIndex"
    hash_key        = "SubjectID"
    range_key       = "testUser"
    projection_type = "KEYS_ONLY"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.user_profile_table_encryption_key.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_table" "client_registry_table" {
  name         = "${var.environment}-client-registry"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "ClientID"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  deletion_protection_enabled = var.dynamo_deletion_protection_enabled

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
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.client_registry_table_encryption_key.arn
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_table" "doc_app_credential_table" {
  name         = "${var.environment}-doc-app-credential"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "SubjectID"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  deletion_protection_enabled = var.dynamo_deletion_protection_enabled

  attribute {
    name = "SubjectID"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.doc_app_credential_table_encryption_key.arn
  }

  lifecycle {
    prevent_destroy = false
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_resource_policy" "doc_app_credential_table_policy" {
  resource_arn = aws_dynamodb_table.doc_app_credential_table.arn
  policy       = data.aws_iam_policy_document.cross_account_doc_app_credential_table_policy.json
}

data "aws_iam_policy_document" "cross_account_doc_app_credential_table_policy" {
  statement {
    effect = "Allow"
    actions = [
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
      "dynamodb:BatchGetItem",
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
    ]
    principals {
      identifiers = [var.orchestration_account_id]
      type        = "AWS"
    }
    resources = ["*"]
  }
}

resource "aws_dynamodb_table" "common_passwords_table" {
  name         = "${var.environment}-common-passwords"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "Password"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  deletion_protection_enabled = var.dynamo_deletion_protection_enabled

  attribute {
    name = "Password"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_table" "account_modifiers_table" {
  name         = "${var.environment}-account-modifiers"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "InternalCommonSubjectIdentifier"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  deletion_protection_enabled = var.dynamo_deletion_protection_enabled

  attribute {
    name = "InternalCommonSubjectIdentifier"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.account_modifiers_table_encryption_key.arn
  }

  lifecycle {
    prevent_destroy = false
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_table" "access_token_store" {
  name         = "${var.environment}-access-token-store"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "AccessToken"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  deletion_protection_enabled = var.dynamo_deletion_protection_enabled

  attribute {
    name = "AccessToken"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.access_token_store_signing_key.arn
  }

  lifecycle {
    prevent_destroy = false
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_table" "auth_code_store" {
  name         = "${var.environment}-auth-code-store"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"
  hash_key     = "AuthCode"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  deletion_protection_enabled = var.dynamo_deletion_protection_enabled

  attribute {
    name = "AuthCode"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.auth_code_store_signing_key.arn
  }

  lifecycle {
    prevent_destroy = false
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_table" "bulk_email_users" {
  name         = "${var.environment}-bulk-email-users"
  count        = local.deploy_bulk_email_users_count
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"

  hash_key = "SubjectID"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  deletion_protection_enabled = var.dynamo_deletion_protection_enabled

  attribute {
    name = "SubjectID"
    type = "S"
  }

  attribute {
    name = "BulkEmailStatus"
    type = "S"
  }

  attribute {
    name = "DeliveryReceiptStatus"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.bulk_email_users_encryption_key.arn
  }

  lifecycle {
    prevent_destroy = false
  }

  global_secondary_index {
    name            = "BulkEmailStatusIndex"
    hash_key        = "BulkEmailStatus"
    projection_type = "ALL"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  global_secondary_index {
    name            = "DeliveryReceiptStatusIndex"
    hash_key        = "DeliveryReceiptStatus"
    projection_type = "ALL"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_table" "email-check-result" {
  name         = "${var.environment}-email-check-result"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"

  hash_key = "Email"

  read_capacity  = var.provision_dynamo ? var.dynamo_default_read_capacity : null
  write_capacity = var.provision_dynamo ? var.dynamo_default_write_capacity : null

  deletion_protection_enabled = var.dynamo_deletion_protection_enabled

  attribute {
    name = "Email"
    type = "S"
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.email_check_result_encryption_key.arn
  }

  lifecycle {
    prevent_destroy = false
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_table" "authentication_attempt_table" {
  name         = "${var.environment}-authentication-attempt"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "InternalSubjectId"
  range_key = "SK"

  attribute {
    name = "InternalSubjectId"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  ttl {
    attribute_name = "TimeToLive"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.authentication_attempt_encryption_key.arn
  }

  lifecycle {
    prevent_destroy = false
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_resource_policy" "client_registry_table_policy" {
  resource_arn = aws_dynamodb_table.client_registry_table.arn
  policy       = data.aws_iam_policy_document.cross_account_table_resource_policy_document.json
}


resource "aws_dynamodb_resource_policy" "user_profile_table_policy" {
  resource_arn = aws_dynamodb_table.user_profile_table.arn
  policy       = data.aws_iam_policy_document.cross_account_table_resource_policy_document.json
}

data "aws_iam_policy_document" "cross_account_table_resource_policy_document" {
  statement {
    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
    ]
    effect = "Allow"
    principals {
      identifiers = [var.orchestration_account_id]
      type        = "AWS"
    }
    resources = ["*"]
  }
}

resource "aws_dynamodb_table" "auth_session_table" {
  name         = "${var.environment}-auth-session"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"

  hash_key = "SessionId"

  attribute {
    name = "SessionId"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.auth_session_table_encryption_key.arn
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}

resource "aws_dynamodb_table" "id_reverification_state" {
  name         = "${var.environment}-id-reverification-state"
  billing_mode = var.provision_dynamo ? "PROVISIONED" : "PAY_PER_REQUEST"

  hash_key = "AuthenticationState"

  attribute {
    name = "AuthenticationState"
    type = "S"
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.id_reverification_state_table_encryption_key.arn
  }

  lifecycle {
    prevent_destroy = true
  }

  tags = (
    var.environment == "integration" || var.environment == "production" ?
    {
      "BackupFrequency" = "Bihourly"
    } : {}
  )
}
