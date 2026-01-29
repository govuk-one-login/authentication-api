common_state_bucket = "digital-identity-prod-tfstate"

# URIs
internal_sector_uri   = "https://identity.account.gov.uk"
access_token_jwks_url = "https://oidc.account.gov.uk/.well-known/jwks.json"

# Notify
notify_template_map = {
  AM_VERIFY_EMAIL_TEMPLATE_ID           = "98fdb807-d0d8-41c8-a1d7-7d0abff06b3c"
  AM_VERIFY_PHONE_NUMBER_TEMPLATE_ID    = "b1b3935d-ffdc-4853-a3cd-a9fce09dbff5"
  EMAIL_UPDATED_TEMPLATE_ID             = "22aac1ce-38c7-45f5-97b2-26ac1a54a235"
  DELETE_ACCOUNT_TEMPLATE_ID            = "1540bdda-fdff-4297-b627-92102e061bfa"
  PHONE_NUMBER_UPDATED_TEMPLATE_ID      = "8907d080-e69c-42c6-8cf5-54ca1558a2e4"
  PASSWORD_UPDATED_TEMPLATE_ID          = "ebf3730c-0769-462b-ab39-7d9a7439bac1"
  BACKUP_METHOD_ADDED_TEMPLATE_ID       = "569ae40c-2631-4de3-9d85-7f8ffd9182e9"
  BACKUP_METHOD_REMOVED_TEMPLATE_ID     = "8c8d2392-cecc-452d-88a5-2bd8418fb257"
  CHANGED_AUTHENTICATOR_APP_TEMPLATE_ID = "de419864-17bf-488c-93e5-da791352e2db"
  CHANGED_DEFAULT_MFA_TEMPLATE_ID       = "2d17c6db-8d2d-42af-95f1-5d096cd74212"
  SWITCHED_MFA_METHODS_TEMPLATE_ID      = "0b856ef8-07d6-4dca-ab6a-8a45044182cc"
}

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

# App-specific
openapi_spec_filename = "openapi_v2.yaml"

# Feature flags
mfa_method_management_api_enabled            = true
ais_call_in_authenticate_enabled             = true
account_management_international_sms_enabled = false
test_signing_key_enabled                     = false
use_access_token_jwks_endpoint               = false

# Logging
cloudwatch_log_retention = 30
logging_endpoint_arns    = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]

# FMS
am_api_fms_tag_value = "accountmanagementprod"

#Vpc endpoint IDs
# di-account-production, di-account-components-production
home_vpc_endpoint_id = ["vpce-0d7972874707185a0", "vpce-08bfce415b33dc8f6"]

# CIDR blocks
new_auth_privatesub_cidr_blocks   = ["10.6.10.0/23", "10.6.12.0/23", "10.6.14.0/23"]
new_auth_protectedsub_cidr_blocks = ["10.6.4.0/23", "10.6.6.0/23", "10.6.8.0/23"]
