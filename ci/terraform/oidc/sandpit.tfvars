environment                    = "sandpit"
keep_lambdas_warm              = false
dns_state_bucket               = null
dns_state_key                  = null
dns_state_role                 = null
shared_state_bucket            = "digital-identity-dev-tfstate"
test_clients_enabled           = "true"
ipv_api_enabled                = true
ipv_authorisation_callback_uri = ""
ipv_authorisation_uri          = ""
ipv_authorisation_client_id    = ""
logging_endpoint_enabled       = false
logging_endpoint_arns          = []
endpoint_memory_size           = 512

enable_api_gateway_execution_request_tracing = true
spot_enabled                                 = false

performance_tuning = {
  register = {
    memory      = 512
    concurrency = 0
  }

  update = {
    memory      = 512
    concurrency = 0
  }
}