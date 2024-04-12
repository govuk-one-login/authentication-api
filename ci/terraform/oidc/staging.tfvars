oidc_api_lambda_zip_file                   = "./artifacts/oidc-api.zip"
frontend_api_lambda_zip_file               = "./artifacts/frontend-api.zip"
client_registry_api_lambda_zip_file        = "./artifacts/client-registry-api.zip"
ipv_api_lambda_zip_file                    = "./artifacts/ipv-api.zip"
doc_checking_app_api_lambda_zip_file       = "./artifacts/doc-checking-app-api.zip"
logging_endpoint_arn                       = ""
logging_endpoint_arns                      = []
shared_state_bucket                        = "di-auth-staging-tfstate"
test_clients_enabled                       = true
internal_sector_uri                        = "https://identity.staging.account.gov.uk"
orch_redirect_uri                          = "https://oidc.staging.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled         = true
remove_retry_limit_registration_email_code = true
lockout_duration                           = 60
reduced_lockout_duration                   = 30

orch_backend_api_gateway_integration_enabled = false
orch_openid_configuration_name               = "staging-orch-be-deploy-OpenIdConfigurationFunction-wWh577dlDcFl"

orch_account_id = "590183975515"
