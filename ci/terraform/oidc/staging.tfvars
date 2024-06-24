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
support_account_creation_count_ttl   = true

orch_account_id                     = "590183975515"
cmk_for_back_channel_logout_enabled = true
txma_audit_encoded_enabled          = true

contra_state_bucket = "di-auth-staging-tfstate"

oidc_origin_domain_enabled  = true
oidc_cloudfront_dns_enabled = true
enforce_cloudfront          = true

orch_doc_app_callback_enabled        = true
orch_token_enabled                   = true
orch_authorisation_enabled           = true
orch_logout_enabled                  = true
orch_ipv_callback_enabled            = true
orch_register_enabled                = true
orch_authentication_callback_enabled = true
auth_spot_response_disabled          = true
orch_auth_code_enabled               = true
orch_userinfo_enabled                = true
