common_state_bucket = "di-auth-development-tfstate"

# URIs
internal_sector_uri = "https://identity.dev.account.gov.uk"

# Sizing
redis_node_size        = "cache.t2.small"
lambda_min_concurrency = 1

# App-specific
openapi_spec_filename = "openapi_v2.yaml"

# Feature flags
mfa_method_management_api_enabled            = true
test_clients_enabled                         = true
ais_call_in_authenticate_enabled             = true
account_management_international_sms_enabled = false

# Durations
lockout_duration                          = 30
otp_code_ttl_duration                     = 120
email_acct_creation_otp_code_ttl_duration = 60

#Vpc endpoint IDs
# di-account-dev, di-account-components-dev
home_vpc_endpoint_id = ["vpce-087ac48f23f28a39b", "vpce-0a7dad1503be13796"]

# CIDR blocks
new_auth_privatesub_cidr_blocks   = ["10.6.10.0/23", "10.6.12.0/23", "10.6.14.0/23"]
new_auth_protectedsub_cidr_blocks = ["10.6.4.0/23", "10.6.6.0/23", "10.6.8.0/23"]
