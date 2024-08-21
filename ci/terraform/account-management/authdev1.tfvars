environment         = "authdev1"
use_localstack      = false
common_state_bucket = "di-auth-development-tfstate"

logging_endpoint_enabled = false
logging_endpoint_arns    = []

endpoint_memory_size   = 1536
lambda_max_concurrency = 0
lambda_min_concurrency = 0

openapi_spec_filename = "openapi.yaml"
