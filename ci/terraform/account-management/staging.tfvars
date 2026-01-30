common_state_bucket = "di-auth-staging-tfstate"

# FMS
am_api_fms_tag_value = "accountmanagementstaging"

# URIs
internal_sector_uri   = "https://identity.staging.account.gov.uk"
access_token_jwks_url = "https://oidc.staging.account.gov.uk/.well-known/jwks.json"

# SNS
legacy_account_deletion_topic_arn     = "arn:aws:sns:eu-west-2:539729775994:UserAccountDeletion"
legacy_account_deletion_topic_key_arn = "arn:aws:kms:eu-west-2:539729775994:key/d33e9077-8d66-4f63-99a1-f90e29b4aabe"

# App-specific
openapi_spec_filename = "openapi_v2.yaml"

# Logging
logging_endpoint_arns = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]

# Sizing
redis_node_size = "cache.t2.small"
performance_tuning = {
  authorizer = {
    memory          = 1536
    concurrency     = 3
    max_concurrency = 10
    scaling_trigger = 0.6
  }
}

lambda_min_concurrency = 1
lambda_max_concurrency = 3

# Feature flags
mfa_method_management_api_enabled            = true
ais_call_in_authenticate_enabled             = true
account_management_international_sms_enabled = false
test_signing_key_enabled                     = true

#Vpc endpoint IDs
# di-account-staging, di-account-components-staging
home_vpc_endpoint_id = ["vpce-0c9ce65be09f99db7", "vpce-0fed7b2d44a0bde33"]

# CIDR blocks
new_auth_privatesub_cidr_blocks   = ["10.6.10.0/23", "10.6.12.0/23", "10.6.14.0/23"]
new_auth_protectedsub_cidr_blocks = ["10.6.4.0/23", "10.6.6.0/23", "10.6.8.0/23"]
