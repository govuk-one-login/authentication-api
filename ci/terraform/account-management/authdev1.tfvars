common_state_bucket  = "di-auth-development-tfstate"
vpc_environment      = "dev"
test_clients_enabled = true

# Feature flags
mfa_method_management_api_enabled = true
ais_call_in_authenticate_enabled  = true

# App-specific
openapi_spec_filename = "openapi_v2.yaml"

# URIs
internal_sector_uri = "https://identity.authdev1.sandpit.account.gov.uk"

# Performance Tuning
snapstart_enabled = true
