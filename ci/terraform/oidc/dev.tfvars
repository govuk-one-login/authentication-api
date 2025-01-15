oidc_api_lambda_zip_file              = "./artifacts/oidc-api.zip"
oidc_api_lambda_dependencies_zip_file = "./artifacts/oidc-api-dependencies.zip"

frontend_api_lambda_zip_file              = "./artifacts/frontend-api.zip"
frontend_api_lambda_dependencies_zip_file = "./artifacts/frontend-api-dependencies.zip"

client_registry_api_lambda_zip_file              = "./artifacts/client-registry-api.zip"
client_registry_api_lambda_dependencies_zip_file = "./artifacts/client-registry-api-dependencies.zip"

ipv_api_lambda_zip_file              = "./artifacts/ipv-api.zip"
ipv_api_lambda_dependencies_zip_file = "./artifacts/ipv-api-dependencies.zip"

doc_checking_app_api_lambda_zip_file              = "./artifacts/doc-checking-app-api.zip"
doc_checking_app_api_lambda_dependencies_zip_file = "./artifacts/doc-checking-app-api-dependencies.zip"

logging_endpoint_arn  = ""
logging_endpoint_arns = []
shared_state_bucket   = "di-auth-development-tfstate"
test_clients_enabled  = true
internal_sector_uri   = "https://identity.dev.account.gov.uk"
call_ticf_cri         = true
ipv_backend_uri       = "https://ipvstub.signin.dev.account.gov.uk"

# AUTH to IPV reverification
# Shared with orch
ipv_authorisation_uri = "https://ipvstub.signin.dev.account.gov.uk/authorize/"
# auth only
ipv_auth_authorize_callback_uri = "https://signin.dev.account.gov.uk/ipv/callback/authorize"
ipv_auth_authorize_client_id    = "authTestClient"

# lockout config
lockout_duration                     = 60
reduced_lockout_duration             = 30
incorrect_password_lockout_count_ttl = 60
lockout_count_ttl                    = 60
otp_code_ttl_duration                = 60

auth_to_orch_token_signing_public_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESgoCw5pZYyGtFpPBV2YfU3DGrDqC
8UKoRGN4gYTbuwAsLkOSYYY8BM7dhSEhgF4DX9i66HXjteogg6mhOZI1mA==
-----END PUBLIC KEY-----
EOT

orch_client_id                     = "orchestrationAuth"
orch_redirect_uri                  = "https://oidc.dev.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled = true

orch_account_id = "816047645251"
is_orch_stubbed = true

contra_state_bucket = "di-auth-development-tfstate"

oidc_cloudfront_enabled = false
