common_state_bucket = "digital-identity-dev-tfstate"

# URIs
internal_sector_uri = "https://identity.integration.account.gov.uk"

# Sizing
redis_node_size        = "cache.t2.small"
lambda_min_concurrency = 1

# App-specific
openapi_spec_filename = "openapi_v2.yaml"

# Feature flags
mfa_method_management_api_enabled            = true
ais_call_in_authenticate_enabled             = true
account_management_international_sms_enabled = false
test_signing_key_enabled                     = false

# Logging
logging_endpoint_arns = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]

# FMS
am_api_fms_tag_value = "accountmanagementint"

#Vpc endpoint IDs
# di-account-integration, di-account-components-integration
home_vpc_endpoint_id = ["vpce-0e594accb3d775457", "vpce-00865f4c00dcdbb83"]

# CIDR blocks
new_auth_privatesub_cidr_blocks   = ["10.6.10.0/23", "10.6.12.0/23", "10.6.14.0/23"]
new_auth_protectedsub_cidr_blocks = ["10.6.4.0/23", "10.6.6.0/23", "10.6.8.0/23"]
