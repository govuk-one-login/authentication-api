common_state_bucket = "digital-identity-prod-tfstate"

# FMS
am_api_fms_tag_value = "accountmanagementprod"

# URIs
internal_sector_uri = "https://identity.account.gov.uk"

# Notify
notify_template_map = {
  AM_VERIFY_EMAIL_TEMPLATE_ID        = "98fdb807-d0d8-41c8-a1d7-7d0abff06b3c"
  AM_VERIFY_PHONE_NUMBER_TEMPLATE_ID = "b1b3935d-ffdc-4853-a3cd-a9fce09dbff5"
  EMAIL_UPDATED_TEMPLATE_ID          = "22aac1ce-38c7-45f5-97b2-26ac1a54a235"
  DELETE_ACCOUNT_TEMPLATE_ID         = "1540bdda-fdff-4297-b627-92102e061bfa"
  PHONE_NUMBER_UPDATED_TEMPLATE_ID   = "8907d080-e69c-42c6-8cf5-54ca1558a2e4"
  PASSWORD_UPDATED_TEMPLATE_ID       = "ebf3730c-0769-462b-ab39-7d9a7439bac1"
}

# Logging
cloudwatch_log_retention = 30
logging_endpoint_arns    = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]

# Sizing
redis_node_size = "cache.m4.xlarge"

performance_tuning = {
  authorizer = {
    memory          = 1536
    concurrency     = 3
    max_concurrency = 10
    scaling_trigger = 0.6
  }
}

lambda_max_concurrency = 10
lambda_min_concurrency = 3

# Feature flags
mfa_method_management_api_enabled = false
