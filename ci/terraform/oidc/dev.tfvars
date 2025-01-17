oidc_api_lambda_zip_file             = "./artifacts/oidc-api.zip"
frontend_api_lambda_zip_file         = "./artifacts/frontend-api.zip"
client_registry_api_lambda_zip_file  = "./artifacts/client-registry-api.zip"
ipv_api_lambda_zip_file              = "./artifacts/ipv-api.zip"
doc_checking_app_api_lambda_zip_file = "./artifacts/doc-checking-app-api.zip"
logging_endpoint_arn                 = ""
logging_endpoint_arns                = []
shared_state_bucket                  = "di-auth-development-tfstate"
test_clients_enabled                 = true
internal_sector_uri                  = "https://identity.dev.account.gov.uk"
orch_redirect_uri                    = "https://oidc.dev.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled   = true
lockout_duration                     = 60
reduced_lockout_duration             = 30
incorrect_password_lockout_count_ttl = 60
# support_account_creation_count_ttl
call_ticf_cri = true
# ticf_cri_service_call_timeout
# support_reauth_signout_enabled
# authentication_attempts_service_enabled

# AUTH to IPV reverification
# Shared with orch
ipv_authorisation_uri = "https://ipvstub.signin.dev.account.gov.uk/authorize/"

orch_account_id = "816047645251"
is_orch_stubbed = true
# orch_environment
# orch_session_table_encryption_key_arn
# cmk_for_back_channel_logout_enabled

contra_state_bucket = "di-auth-development-tfstate"

#orch_openid_configuration_enabled
#orch_doc_app_callback_enabled
#orch_token_enabled
#orch_jwks_enabled
#orch_authorisation_enabled
#orch_logout_enabled
#orch_ipv_callback_enabled
#orch_register_enabled
#orch_authentication_callback_enabled
#auth_spot_response_disabled
#orch_auth_code_enabled
#orch_userinfo_enabled
#orch_storage_token_jwk_enabled
#orch_trustmark_enabled

#reauth_enter_email_count_ttl
#reauth_enter_password_count_ttl
#reauth_enter_sms_code_count_ttl
#reauth_enter_auth_app_code_count_ttl

#
# DEV only
#
auth_to_orch_token_signing_public_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESgoCw5pZYyGtFpPBV2YfU3DGrDqC
8UKoRGN4gYTbuwAsLkOSYYY8BM7dhSEhgF4DX9i66HXjteogg6mhOZI1mA==
-----END PUBLIC KEY-----
EOT

oidc_cloudfront_enabled = false

#
#  Possibly not needed
#

# lockout config
lockout_count_ttl     = 60
otp_code_ttl_duration = 60
