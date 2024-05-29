environment         = "authdev1"
use_localstack      = false
common_state_bucket = "di-auth-development-tfstate"
dns_state_bucket    = null
dns_state_key       = null
dns_state_role      = null

logging_endpoint_enabled = false
logging_endpoint_arns    = []

endpoint_memory_size   = 1536
lambda_max_concurrency = 0
lambda_min_concurrency = 0

lockout_duration                          = 30
otp_code_ttl_duration                     = 120
email_acct_creation_otp_code_ttl_duration = 60
