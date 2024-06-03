internal_sector_uri = "https://identity.staging.account.gov.uk"


performance_tuning = {
  authorizer = {
    memory          = 1536
    concurrency     = 3
    max_concurrency = 10
    scaling_trigger = 0.6
  }
}

lambda_max_concurrency = 3
lambda_min_concurrency = 1
endpoint_memory_size   = 1536
scaling_trigger        = 0.6

logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]

common_state_bucket = "di-auth-staging-tfstate"

support_email_check_enabled = true
