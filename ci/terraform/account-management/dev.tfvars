logging_endpoint_arn  = ""
logging_endpoint_arns = []
lambda_zip_file       = "./artifacts/account-management-api.zip"
common_state_bucket   = "di-auth-development-tfstate"

internal_sector_uri = "https://identity.dev.account.gov.uk"

lambda_max_concurrency = 0
lambda_min_concurrency = 1
endpoint_memory_size   = 1536
scaling_trigger        = 0.6

lockout_duration                          = 30
otp_code_ttl_duration                     = 120
email_acct_creation_otp_code_ttl_duration = 60

openapi_spec_filename = "openapi_v2.yaml"
