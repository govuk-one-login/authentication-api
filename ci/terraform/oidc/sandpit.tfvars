environment                         = "sandpit"
notify_api_key                      = "123456"
keep_lambdas_warm                   = false
dns_state_bucket                    = null
dns_state_key                       = null
dns_state_role                      = null
account_management_url              = null
shared_state_bucket                 = "digital-identity-dev-tfstate"
test_client_verify_email_otp        = "123456"
test_client_verify_phone_number_otp = "123456"
test_clients_enabled                = "true"
service_domain_name                 = "auth.ida.digital.cabinet-office.gov.uk"
frontend_base_url                   = "http://localhost:3000"
oidc_api_url                        = "api.sandpit.auth.ida.digital.cabinet-office.gov.uk"
frontend_api_url                    = "auth.sandpit.auth.ida.digital.cabinet-office.gov.uk"

enable_api_gateway_execution_request_tracing = true