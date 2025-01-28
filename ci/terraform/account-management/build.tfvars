common_state_bucket = "digital-identity-dev-tfstate"

# URIs
internal_sector_uri = "https://identity.build.account.gov.uk"

# Logging
logging_endpoint_arns = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]

# Sizing
redis_node_size        = "cache.t2.small"
lambda_min_concurrency = 1
