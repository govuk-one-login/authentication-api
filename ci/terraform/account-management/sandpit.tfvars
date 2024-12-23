environment         = "sandpit"
common_state_bucket = "digital-identity-dev-tfstate"

logging_endpoint_enabled = false
logging_endpoint_arns    = []

endpoint_memory_size   = 1536
lambda_max_concurrency = 0
lambda_min_concurrency = 0

lockout_duration                          = 30
otp_code_ttl_duration                     = 120
email_acct_creation_otp_code_ttl_duration = 60
support_email_check_enabled               = true

openapi_spec_filename = "openapi_v2.yaml"
