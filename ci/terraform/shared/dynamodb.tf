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

  attribute {
    name = "MigratedPassword"
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
    name            = "TestUserIndex"
    hash_key        = "SubjectID"
    range_key       = "testUser"
    projection_type = "KEYS_ONLY"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  global_secondary_index {
    name            = "UnmigratedGovukAccountUsers"
    hash_key        = "SubjectID"
    range_key       = "MigratedPassword"
    projection_type = "KEYS_ONLY"
    read_capacity   = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity  = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.user_credentials_table_encryption_key.arn
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

  attribute {
    name = "PhoneNumber"
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

  global_secondary_index {
    name               = "PhoneNumberIndex"
    hash_key           = "PhoneNumber"
    projection_type    = "INCLUDE"
    non_key_attributes = ["PhoneNumberVerified"]
    read_capacity      = var.provision_dynamo ? var.dynamo_default_read_capacity : null
    write_capacity     = var.provision_dynamo ? var.dynamo_default_write_capacity : null
  }

  global_secondary_index {
    name            = "CountUserIndex"
    hash_key        = "testUser"
    range_key       = "accountVerified"
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

resource "aws_dynamodb_table" "identity_credentials_table" {
  name         = "${var.environment}-identity-credentials"
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
    kms_key_arn = aws_kms_key.identity_credentials_table_encryption_key.arn
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

locals {
  authorized_account_ids = local.allow_cross_account_access ? [var.auth_new_account_id, var.orchestration_account_id] : [var.orchestration_account_id]
}

resource "aws_dynamodb_resource_policy" "client_registry_table_policy" {
  resource_arn = aws_dynamodb_table.client_registry_table.arn
  policy       = data.aws_iam_policy_document.cross_account_table_resource_policy_document.json
}

resource "aws_dynamodb_resource_policy" "identity_credentials_table_policy" {
  resource_arn = aws_dynamodb_table.identity_credentials_table.arn
  policy       = data.aws_iam_policy_document.cross_account_identity_credentials_table_resource_policy_document.json
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
      identifiers = local.authorized_account_ids
      type        = "AWS"
    }
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "cross_account_identity_credentials_table_resource_policy_document" {
  statement {
    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:DescribeTable",
      "dynamodb:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem",
    ]
    effect = "Allow"
    principals {
      identifiers = local.authorized_account_ids
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

## DynamoDB Resource Policies
## These policies are used to allow cross-account access to the DynamoDB tables

resource "aws_dynamodb_resource_policy" "user_credentials_table" {
  count        = local.allow_cross_account_access ? 1 : 0
  resource_arn = aws_dynamodb_table.user_credentials_table.arn
  policy       = data.aws_iam_policy_document.auth_cross_account_table_resource_policy_document[0].json
}

resource "aws_dynamodb_resource_policy" "common_passwords_table" {
  count        = local.allow_cross_account_access ? 1 : 0
  resource_arn = aws_dynamodb_table.common_passwords_table.arn
  policy       = data.aws_iam_policy_document.auth_cross_account_table_resource_policy_document[0].json
}

resource "aws_dynamodb_resource_policy" "account_modifiers_table" {
  count        = local.allow_cross_account_access ? 1 : 0
  resource_arn = aws_dynamodb_table.account_modifiers_table.arn
  policy       = data.aws_iam_policy_document.auth_cross_account_table_resource_policy_document[0].json
}

resource "aws_dynamodb_resource_policy" "access_token_store" {
  count        = local.allow_cross_account_access ? 1 : 0
  resource_arn = aws_dynamodb_table.access_token_store.arn
  policy       = data.aws_iam_policy_document.auth_cross_account_table_resource_policy_document[0].json
}

resource "aws_dynamodb_resource_policy" "auth_code_store" {
  count        = local.allow_cross_account_access ? 1 : 0
  resource_arn = aws_dynamodb_table.auth_code_store.arn
  policy       = data.aws_iam_policy_document.auth_cross_account_table_resource_policy_document[0].json
}

resource "aws_dynamodb_resource_policy" "email-check-result" {
  count        = local.allow_cross_account_access ? 1 : 0
  resource_arn = aws_dynamodb_table.email-check-result.arn
  policy       = data.aws_iam_policy_document.auth_cross_account_table_resource_policy_document[0].json
}

resource "aws_dynamodb_resource_policy" "authentication_attempt_table" {
  count        = local.allow_cross_account_access ? 1 : 0
  resource_arn = aws_dynamodb_table.authentication_attempt_table.arn
  policy       = data.aws_iam_policy_document.auth_cross_account_table_resource_policy_document[0].json
}

resource "aws_dynamodb_resource_policy" "auth_session_table" {
  count        = local.allow_cross_account_access ? 1 : 0
  resource_arn = aws_dynamodb_table.auth_session_table.arn
  policy       = data.aws_iam_policy_document.auth_cross_account_table_resource_policy_document[0].json
}

resource "aws_dynamodb_resource_policy" "id_reverification_state" {
  count        = local.allow_cross_account_access ? 1 : 0
  resource_arn = aws_dynamodb_table.id_reverification_state.arn
  policy       = data.aws_iam_policy_document.auth_cross_account_table_resource_policy_document[0].json
}


locals {
  allowed_env                = ["dev", "authdev1", "authdev2", "sandpit"]
  allow_cross_account_access = contains(local.allowed_env, var.environment)
}


data "aws_iam_policy_document" "auth_cross_account_table_resource_policy_document" {
  #checkov:skip=CKV_AWS_111:Ensure IAM policies does not allow write access without constraints
  #checkov:skip=CKV_AWS_356:Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions
  count = local.allow_cross_account_access ? 1 : 0
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
      identifiers = [var.auth_new_account_id]
      type        = "AWS"
    }
    resources = ["*"]
  }
}
