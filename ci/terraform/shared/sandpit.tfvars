environment                 = "sandpit"
common_state_bucket         = "digital-identity-dev-tfstate"
keep_lambdas_warm           = false
redis_node_size             = "cache.t2.micro"
test_client_email_allowlist = "testclient.user1@digital.cabinet-office.gov.uk,testclient.user2@digital.cabinet-office.gov.uk"
password_pepper             = "fake-pepper"

enable_api_gateway_execution_request_tracing = true