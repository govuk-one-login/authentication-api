common_state_bucket = "di-auth-development-tfstate"

# URIs
internal_sector_uri = "https://identity.dev.account.gov.uk"

# Durations
lockout_duration                          = 30
otp_code_ttl_duration                     = 120
email_acct_creation_otp_code_ttl_duration = 60

# App-specific
openapi_spec_filename = "openapi_v2.yaml"

# Sizing
redis_node_size        = "cache.t2.small"
lambda_min_concurrency = 1

# Feature flags
mfa_method_management_api_enabled = true
test_clients_enabled              = true
ais_call_in_authenticate_enabled  = true

#Vpc endpoint IDs
home_vpc_endpoint_id = "vpce-087ac48f23f28a39b"
