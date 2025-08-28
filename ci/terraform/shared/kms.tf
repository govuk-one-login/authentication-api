resource "aws_kms_key" "id_token_signing_key" {
  description              = "KMS signing key for ID tokens"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  policy = data.aws_iam_policy_document.id_token_signing_key_access_policy.json

}

resource "aws_kms_alias" "id_token_signing_key_alias" {
  name          = "alias/${var.environment}-id-token-signing-key-alias"
  target_key_id = aws_kms_key.id_token_signing_key.key_id
}

data "aws_iam_policy_document" "id_token_signing_key_access_policy" {
  statement {
    sid    = "DefaultAccessPolicy"
    effect = "Allow"

    actions = [
      "kms:*"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowOrchAccessToKmsIdTokenSigningKey-${var.environment}"
    effect = "Allow"

    actions = [
      "kms:GetPublicKey",
      "kms:Sign"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.orchestration_account_id}:root"]
    }
  }
}

data "aws_iam_policy_document" "kms_policy_document" {
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:GetPublicKey",
    ]
    resources = [
      aws_kms_key.id_token_signing_key.arn,
    ]
  }
}

data "aws_iam_policy_document" "kms_signing_policy_document" {
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = [
      aws_kms_key.id_token_signing_key.arn,
    ]
  }
}

resource "aws_iam_policy" "lambda_kms_signing_policy" {
  name        = "${var.environment}-standard-lambda-kms-signing-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing"

  policy = data.aws_iam_policy_document.kms_signing_policy_document.json
}



resource "aws_iam_policy" "lambda_kms_policy" {
  name        = "${var.environment}-standard-lambda-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda"

  policy = data.aws_iam_policy_document.kms_policy_document.json
}


resource "aws_iam_role_policy_attachment" "lambda_kms" {
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_kms_policy.arn
}


resource "aws_iam_role_policy_attachment" "lambda_kms_signing_policy" {
  role       = aws_iam_role.token_lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_kms_signing_policy.arn
}


# Audit signing key

resource "aws_kms_key" "audit_payload_signing_key" {
  description              = "KMS signing key for audit payloads"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

}

resource "aws_kms_alias" "audit_payload_signing_key_alias" {
  name          = "alias/${var.environment}-audit-payload-signing-key-alias"
  target_key_id = aws_kms_key.audit_payload_signing_key.key_id
}

data "aws_iam_policy_document" "audit_payload_kms_signing_policy_document" {
  statement {
    sid    = "AllowAccessToKmsAuditSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
      "kms:Verify"
    ]
    resources = [
      aws_kms_key.audit_payload_signing_key.arn,
    ]
  }
}


resource "aws_iam_policy" "audit_signing_key_lambda_kms_signing_policy" {
  name        = "${var.environment}-standard-lambda-audit-payload-kms-signing-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda which allows signing of audit payloads"

  policy = data.aws_iam_policy_document.audit_payload_kms_signing_policy_document.json
}


resource "aws_iam_role_policy_attachment" "attach_audit_signing_key_policy_default" {
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn
}


resource "aws_iam_role_policy_attachment" "attach_audit_signing_key_policy_token" {
  role       = aws_iam_role.token_lambda_iam_role.name
  policy_arn = aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn
}


resource "aws_iam_role_policy_attachment" "attach_audit_signing_key_policy_dynamo" {
  role       = aws_iam_role.dynamo_sqs_lambda_iam_role.name
  policy_arn = aws_iam_policy.audit_signing_key_lambda_kms_signing_policy.arn
}


# Cloudwatch Log Encryption
data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "cloudwatch" {
  policy_id = "key-policy-cloudwatch"
  statement {
    sid = "Enable IAM User Permissions for root user"
    actions = [
      "kms:*",
    ]
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = [
        format(
          "arn:%s:iam::%s:root",
          data.aws_partition.current.partition,
          data.aws_caller_identity.current.account_id
        )
      ]
    }
    resources = ["*"]
  }
  statement {
    sid = "AllowCloudWatchLogs"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:Describe*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
    ]
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = [
        format(
          "logs.%s.amazonaws.com",
          data.aws_region.current.name
        )
      ]
    }
    resources = ["*"]
  }
}

resource "aws_kms_key" "cloudwatch_log_encryption" {
  description             = "KMS key for Cloudwatch logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.cloudwatch.json

}

resource "aws_kms_key" "lambda_env_vars_encryption_key" {
  description              = "KMS encryption key for lambda environment variables"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true

}

resource "aws_kms_alias" "lambda_env_vars_encryption_key_alias" {
  name          = "alias/${var.environment}-lambda-env-vars-encryption-key-alias"
  target_key_id = aws_kms_key.lambda_env_vars_encryption_key.key_id
}

data "aws_iam_policy_document" "lambda_env_vars_encryption_key_policy_document" {
  statement {
    sid    = "AllowAccessToLambdaEnvVarsKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:GetPublicKey"
    ]
    resources = [
      aws_kms_key.lambda_env_vars_encryption_key.arn,
    ]
  }
}


resource "aws_iam_policy" "lambda_env_vars_encryption_kms_policy" {
  name        = "${var.environment}-lambda-env-vars-encryption-key-kms-policy"
  path        = "/"
  description = "IAM policy for managing KMS connection for a lambda environment variable encryption"

  policy = data.aws_iam_policy_document.lambda_env_vars_encryption_key_policy_document.json
}


resource "aws_iam_role_policy_attachment" "lambda_env_vars_encryption_kms_policy" {
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_env_vars_encryption_kms_policy.arn
}

### Events flow encryption key

resource "aws_kms_key" "events_topic_encryption" {
  description = "alias/${var.environment}/events-encryption-key"

  policy              = data.aws_iam_policy_document.events_encryption_key_permissions.json
  enable_key_rotation = true
}

resource "aws_kms_alias" "events_topic_encryption_alias" {
  name          = "alias/${var.environment}-events-encryption-key-alias"
  target_key_id = aws_kms_key.events_topic_encryption.id
}

data "aws_iam_policy_document" "events_encryption_key_permissions" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-events-encryption-key-policy"

  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "Allow use of the key by SQS/SNS"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt"
    ]
    resources = ["*"]

    principals {
      type = "Service"
      identifiers = [
        "sns.amazonaws.com",
        "sqs.amazonaws.com"
      ]
    }
  }
}

# Doc Checking App Authentication Signing KMS key

resource "aws_kms_key" "doc_app_auth_signing_key" {
  description              = "KMS signing key for authentication to the Doc Checking App"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"


  policy = data.aws_iam_policy_document.cross_account_doc_app_auth_signing_key_policy.json
}

data "aws_iam_policy_document" "cross_account_doc_app_auth_signing_key_policy" {
  statement {
    sid    = "DefaultAccessPolicy"
    effect = "Allow"

    actions = [
      "kms:*"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowOrchAccessToKmsDocAppSigningKey-${var.environment}"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.orchestration_account_id}:root"]
    }
  }

  statement {
    sid    = "AllowAuthAccessToKmsDocAppSigningKey-${var.environment}"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.auth_new_account_id}:root"]
    }
  }
}

resource "aws_kms_alias" "doc_app_auth_signing_key_alias" {
  name          = "alias/${var.environment}-doc-app-auth-kms-key-alias"
  target_key_id = aws_kms_key.doc_app_auth_signing_key.key_id
}

# Orchestration to Authentication Signing KMS key

resource "aws_kms_key" "orchestration_to_auth_signing_key" {
  description              = "KMS signing key for Orchestration signing requests to Authentication"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  policy = data.aws_iam_policy_document.orch_to_auth_signing_key_access_policy.json

}

resource "aws_kms_alias" "orchestration_to_auth_signing_key_alias" {
  name          = "alias/${var.environment}-orch-signing-key-alias"
  target_key_id = aws_kms_key.orchestration_to_auth_signing_key.key_id
}

data "aws_iam_policy_document" "orch_to_auth_signing_key_access_policy" {
  statement {
    sid    = "DefaultAccessPolicy"
    effect = "Allow"

    actions = [
      "kms:*"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowOrchAccessToKmsOrchToAuthSigningKey-${var.environment}"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.orchestration_account_id}:root"]
    }
  }
}

# Authorization Code store Signing KMS key

resource "aws_kms_key" "auth_code_store_signing_key" {
  description              = "KMS signing key for Authorization code store in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.auth_dynamo_table_encryption_key_access_policy.json
}

resource "aws_kms_alias" "auth_code_store_signing_key_alias" {
  name          = "alias/${var.environment}-auth-code-store-table-encryption-key"
  target_key_id = aws_kms_key.auth_code_store_signing_key.key_id
}

# Authorization Token endpoint Signing KMS key

resource "aws_kms_key" "auth_id_token_signing_key" {
  description              = "KMS signing key for ID tokens issued by Authentication to Orchestration"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

}

resource "aws_kms_alias" "auth_id_token_signing_key_alias" {
  name          = "alias/${var.environment}-auth-id-token-signing-key-alias"
  target_key_id = aws_kms_key.auth_id_token_signing_key.key_id
}
resource "aws_kms_key" "access_token_store_signing_key" {
  description              = "KMS signing key for Access Token store in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.auth_dynamo_table_encryption_key_access_policy.json
}

resource "aws_kms_alias" "access_token_store_signing_key_alias" {
  name          = "alias/${var.environment}-access-token-store-table-encryption-key"
  target_key_id = aws_kms_key.access_token_store_signing_key.key_id
}

resource "aws_kms_key" "bulk_email_users_encryption_key" {
  description              = "KMS encryption key for bulk email users table in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.auth_dynamo_table_encryption_key_access_policy.json
}

resource "aws_kms_alias" "bulk_email_users_encryption_key_alias" {
  name          = "alias/${var.environment}-bulk-email-users-table-encryption-key"
  target_key_id = aws_kms_key.bulk_email_users_encryption_key.key_id
}

resource "aws_kms_key" "account_modifiers_table_encryption_key" {
  description              = "KMS encryption key for account modifiers table in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.auth_dynamo_table_encryption_key_access_policy.json
}

resource "aws_kms_alias" "account_modifiers_table_encryption_key_alias" {
  name          = "alias/${var.environment}-account-modifiers-table-encryption-key"
  target_key_id = aws_kms_key.account_modifiers_table_encryption_key.key_id
}

resource "aws_kms_key" "user_credentials_table_encryption_key" {
  description              = "KMS encryption key for user credentials table in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.auth_dynamo_table_encryption_key_access_policy.json
}

resource "aws_kms_alias" "user_credentials_table_encryption_key_alias" {
  name          = "alias/${var.environment}-user-credentials-table-encryption-key"
  target_key_id = aws_kms_key.user_credentials_table_encryption_key.key_id
}

resource "aws_kms_key" "common_passwords_table_encryption_key" {
  description              = "KMS encryption key for common passwords table in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.auth_dynamo_table_encryption_key_access_policy.json
}

resource "aws_kms_alias" "common_passwords_table_encryption_key_alias" {
  name          = "alias/${var.environment}-common-passwords-table-encryption-key"
  target_key_id = aws_kms_key.common_passwords_table_encryption_key.key_id
}

resource "aws_kms_key" "client_registry_table_encryption_key" {
  description              = "KMS encryption key for client registry table in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.cross_account_table_encryption_key_access_policy.json
}

resource "aws_kms_alias" "client_registry_table_encryption_key_alias" {
  name          = "alias/${var.environment}-client-registry-table-encryption-key"
  target_key_id = aws_kms_key.client_registry_table_encryption_key.key_id
}


data "aws_iam_policy_document" "cross_account_table_encryption_key_access_policy" {
  statement {
    sid    = "key-policy-dynamodb"
    effect = "Allow"
    actions = [
      "kms:*",
    ]
    principals {
      identifiers = [data.aws_caller_identity.current.account_id]
      type        = "AWS"
    }
    resources = ["*"]
  }

  statement {
    sid    = "Allow Orch access to dynamo encryption key"
    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [var.orchestration_account_id]
    }
  }

  statement {
    sid    = "Allow Auth access to dynamo table encryption key"
    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey",
    ]
    principals {
      type = "AWS"
      identifiers = [
        format(
          "arn:%s:iam::%s:root",
          data.aws_partition.current.partition,
          var.auth_new_account_id
        )
      ]
    }
    resources = ["*"]
  }
}

resource "aws_kms_key" "user_profile_table_encryption_key" {
  description              = "KMS encryption key for user profile table in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true

  policy = data.aws_iam_policy_document.cross_account_table_encryption_key_access_policy.json

}

resource "aws_kms_alias" "user_profile_table_encryption_key_alias" {
  name          = "alias/${var.environment}-user-profile-table-encryption-key"
  target_key_id = aws_kms_key.user_profile_table_encryption_key.key_id
}

resource "aws_kms_key" "email_check_result_encryption_key" {
  description              = "KMS encryption key for email check result table in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.auth_dynamo_table_encryption_key_access_policy.json
}

resource "aws_kms_alias" "email_check_result_encryption_key_alias" {
  name          = "alias/${var.environment}-email-check-result-table-encryption-key"
  target_key_id = aws_kms_key.email_check_result_encryption_key.key_id
}

resource "aws_kms_key" "pending_email_check_queue_encryption_key" {
  description              = "KMS signing key for encrypting pending email check audit queue at rest"
  deletion_window_in_days  = 30
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  enable_key_rotation      = true
}

data "aws_iam_policy_document" "pending_email_check_queue_encryption_key_access_policy" {
  statement {
    sid    = "DefaultAccessPolicy"
    effect = "Allow"

    actions = [
      "kms:*"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowPendingEmailCheckAccessToKmsAuditEncryptionKey-${var.environment}"
    effect = "Allow"

    actions = [
      "kms:Decrypt"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.auth_check_account_id}:root"]
    }
  }

  statement {
    sid    = "Allow Auth access to dynamo table encryption key"
    effect = "Allow"

    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.auth_new_account_id}:root"]
    }
    resources = ["*"]
  }
  #checkov:skip=CKV_AWS_109:Root requires all kms:* actions access
  #checkov:skip=CKV_AWS_111:Root requires all kms:* actions access
  #checkov:skip=CKV_AWS_356:Policy cannot self-reference the kms key, so resources wildcard is required
}

resource "aws_kms_alias" "pending_email_check_queue_encryption_key_alias" {
  name          = "alias/${var.environment}-pending-email-check-queue-encryption-key"
  target_key_id = aws_kms_key.pending_email_check_queue_encryption_key.key_id
}

data "aws_iam_policy_document" "pending_email_check_combined_policy" {
  source_policy_documents = [
    data.aws_iam_policy_document.pending_email_check_queue_encryption_key_access_policy.json,
    data.aws_iam_policy_document.allow_experian_to_pending_email_check_dlq_encryption_policy.json
  ]
}

data "aws_iam_policy_document" "allow_experian_to_pending_email_check_dlq_encryption_policy" {
  statement {
    sid    = "AllowExperianToPendingEmailCheckDLQEncryption"
    effect = "Allow"

    actions = [
      "kms:GenerateDataKey"
    ]
    resources = [aws_kms_key.pending_email_check_queue_encryption_key.arn]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.auth_check_account_id}:root"]
    }
  }
}

resource "aws_kms_key_policy" "pending_email_check_queue_policy" {
  key_id = aws_kms_key.pending_email_check_queue_encryption_key.id
  policy = data.aws_iam_policy_document.pending_email_check_combined_policy.json
}

resource "aws_kms_key" "authentication_attempt_encryption_key" {
  description              = "KMS encryption key for authentication attempt table in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.auth_dynamo_table_encryption_key_access_policy.json
}

resource "aws_kms_alias" "authentication_attempt_encryption_key_alias" {
  name          = "alias/${var.environment}-authentication-attempt-table-encryption-key"
  target_key_id = aws_kms_key.authentication_attempt_encryption_key.key_id
}

resource "aws_kms_key" "auth_session_table_encryption_key" {
  description              = "KMS encryption key for auth session table in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.auth_dynamo_table_encryption_key_access_policy.json
}

resource "aws_kms_alias" "auth_session_table_encryption_key_alias" {
  name          = "alias/${var.environment}-auth-session-table-encryption-key"
  target_key_id = aws_kms_key.auth_session_table_encryption_key.key_id
}


resource "aws_kms_key" "id_reverification_state_table_encryption_key" {
  description              = "KMS encryption key for id_reverification_state table in DynamoDB"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.auth_dynamo_table_encryption_key_access_policy.json
}

resource "aws_kms_alias" "id_reverification_state_table_encryption_key_alias" {
  name          = "alias/${var.environment}-id-reverification-state-table-encryption-key"
  target_key_id = aws_kms_key.id_reverification_state_table_encryption_key.key_id
}

## KMS Key policy to Allow access to the KMS key for the new authentication AWS account to access DynamoDB table


data "aws_iam_policy_document" "auth_dynamo_table_encryption_key_access_policy" {
  #checkov:skip=CKV_AWS_109:Root requires all kms:* actions access
  #checkov:skip=CKV_AWS_111:Root requires all kms:* actions access
  #checkov:skip=CKV_AWS_356:Policy cannot self-reference the kms key, so resources wildcard is required
  statement {
    sid    = "DefaultAccessPolicy"
    effect = "Allow"

    actions = [
      "kms:*"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "Allow Auth access to dynamo table encryption key"
    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey",
    ]
    principals {
      type = "AWS"
      identifiers = [
        format(
          "arn:%s:iam::%s:root",
          data.aws_partition.current.partition,
          var.auth_new_account_id
        )
      ]
    }
    resources = ["*"]
  }
}

## Frontend KMS key for signing JWT tokens
resource "aws_kms_key" "authentication_encryption_key" {
  description              = "KMS encryption key for decrypting requests from Orchestration"
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "RSA_2048"
}

resource "aws_kms_key_policy" "authentication_encryption_key_access_policy" {
  key_id = aws_kms_key.authentication_encryption_key.id
  policy = data.aws_iam_policy_document.authentication_encryption_key_access_policy_document.json
}

data "aws_iam_policy_document" "authentication_encryption_key_access_policy_document" {
  #checkov:skip=CKV_AWS_109:Root requires all kms:* actions access
  #checkov:skip=CKV_AWS_111:Root requires all kms:* actions access
  #checkov:skip=CKV_AWS_356:Policy cannot self-reference the kms key, so resources wildcard is required
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    actions = [
      "kms:*"
    ]
    principals {
      type = "AWS"
      identifiers = [
        format(
          "arn:%s:iam::%s:root",
          data.aws_partition.current.partition,
          data.aws_caller_identity.current.account_id
        )
      ]
    }
    resources = ["*"]
  }

  statement {
    sid    = "AllowAccessToAuthenticationKmsEncryptionKey"
    effect = "Allow"

    actions = [
      "kms:Decrypt*"
    ]
    principals {
      type = "AWS"
      identifiers = [
        format(
          "arn:%s:iam::%s:root",
          data.aws_partition.current.partition,
          var.auth_new_account_id
        )
      ]
    }
    resources = ["*"]
  }
}

resource "aws_kms_alias" "authentication_encryption_key_alias" {
  name          = "alias/${var.environment}-authentication-encryption-key-alias"
  target_key_id = aws_kms_key.authentication_encryption_key.key_id
}
