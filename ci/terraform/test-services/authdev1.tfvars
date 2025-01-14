environment         = "authdev1"
shared_state_bucket = "di-auth-development-tfstate"
vpc_environment     = "dev"

synthetics_users = "any.user@digital.cabinet-office.gov.uk"

logging_endpoint_enabled = false
logging_endpoint_arns    = []

lambda_min_concurrency      = 0
lambda_max_concurrency      = 0
test_services_use_snapstart = true
