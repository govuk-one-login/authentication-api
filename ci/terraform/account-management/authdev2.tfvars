common_state_bucket  = "di-auth-development-tfstate"
vpc_environment      = "dev"
test_clients_enabled = true

# Feature flags
mfa_method_management_api_enabled            = true
ais_call_in_authenticate_enabled             = true
account_management_international_sms_enabled = false

# App-specific
openapi_spec_filename = "openapi_v2.yaml"

# URIs
internal_sector_uri = "https://identity.authdev2.sandpit.account.gov.uk"

# CIDR blocks
new_auth_privatesub_cidr_blocks   = ["10.6.10.0/23", "10.6.12.0/23", "10.6.14.0/23"]
new_auth_protectedsub_cidr_blocks = ["10.6.4.0/23", "10.6.6.0/23", "10.6.8.0/23"]
