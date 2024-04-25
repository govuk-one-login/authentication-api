oidc_api_lambda_zip_file             = "./artifacts/oidc-api.zip"
frontend_api_lambda_zip_file         = "./artifacts/frontend-api.zip"
client_registry_api_lambda_zip_file  = "./artifacts/client-registry-api.zip"
ipv_api_lambda_zip_file              = "./artifacts/ipv-api.zip"
doc_checking_app_api_lambda_zip_file = "./artifacts/doc-checking-app-api.zip"
logging_endpoint_arn                 = ""
logging_endpoint_arns                = []
shared_state_bucket                  = "di-auth-staging-tfstate"
test_clients_enabled                 = true
internal_sector_uri                  = "https://identity.staging.account.gov.uk"
orch_redirect_uri                    = "https://oidc.staging.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled   = true
lockout_duration                     = 7200
reduced_lockout_duration             = 900
incorrect_password_lockout_count_ttl = 7200

orch_openid_configuration_name = "staging-orch-be-deploy-OpenIdConfigurationFunction-wWh577dlDcFl"

orch_account_id                                  = "590183975515"
orch_doc_app_callback_enabled                    = true
orch_doc_app_callback_name                       = "staging-orch-be-deploy-DocAppCallbackFunction-9CU8q80ZrDRZ"
back_channel_logout_cross_account_access_enabled = true
kms_cross_account_access_enabled                 = true
cmk_for_back_channel_logout_enabled              = true

remove_ipv_callback_from_spot_queue_resource_policy = true
