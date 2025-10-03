common_state_bucket = "di-auth-development-tfstate"
vpc_environment     = "dev"

# FMS
am_api_fms_tag_value = "accountmanagementsp"

# Durations
lockout_duration                          = 30
otp_code_ttl_duration                     = 120
email_acct_creation_otp_code_ttl_duration = 60

# Feature Flags
mfa_method_management_api_enabled = true
test_clients_enabled              = true

openapi_spec_filename = "openapi_v2.yaml"

# URIs
internal_sector_uri = "https://identity.sandpit.account.gov.uk"
