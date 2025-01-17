oidc_api_lambda_zip_file             = "./artifacts/oidc-api.zip"
frontend_api_lambda_zip_file         = "./artifacts/frontend-api.zip"
client_registry_api_lambda_zip_file  = "./artifacts/client-registry-api.zip"
ipv_api_lambda_zip_file              = "./artifacts/ipv-api.zip"
doc_checking_app_api_lambda_zip_file = "./artifacts/doc-checking-app-api.zip"
logging_endpoint_arn                 = ""
logging_endpoint_arns                = []
shared_state_bucket                  = "digital-identity-dev-tfstate"
test_clients_enabled                 = true
internal_sector_uri                  = "https://identity.build.account.gov.uk"
orch_redirect_uri                    = "https://oidc.build.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled   = true
lockout_duration                     = 60
reduced_lockout_duration             = 30
incorrect_password_lockout_count_ttl = 60
support_account_creation_count_ttl   = true
call_ticf_cri                        = true
# ticf_cri_service_call_timeout
support_reauth_signout_enabled          = true
authentication_attempts_service_enabled = true

# AUTH to IPV reverification
# Shared with orch
ipv_authorisation_uri = "https://identity.build.account.gov.uk/oauth2/authorize"

orch_account_id                       = "767397776536"
is_orch_stubbed                       = false
orch_environment                      = "build"
orch_session_table_encryption_key_arn = "arn:aws:kms:eu-west-2:767397776536:key/b7cb6340-0d22-4b6a-8702-b5ec17d4f979"
#cmk_for_back_channel_logout_enabled

contra_state_bucket = "digital-identity-dev-tfstate"

orch_openid_configuration_enabled    = true
orch_doc_app_callback_enabled        = true
orch_token_enabled                   = true
orch_jwks_enabled                    = true
orch_authorisation_enabled           = true
orch_logout_enabled                  = true
orch_ipv_callback_enabled            = true
orch_register_enabled                = true
orch_authentication_callback_enabled = true
auth_spot_response_disabled          = true
orch_ipv_jwks_enabled                = true
orch_auth_code_enabled               = true
orch_userinfo_enabled                = true
orch_storage_token_jwk_enabled       = true
orch_trustmark_enabled               = true

#reauth_enter_email_count_ttl
#reauth_enter_password_count_ttl
#reauth_enter_sms_code_count_ttl
#reauth_enter_auth_app_code_count_ttl

#
# build specific
#

# lockout config
lockout_count_ttl                         = 60
otp_code_ttl_duration                     = 60
account_creation_lockout_count_ttl        = 60
email_acct_creation_otp_code_ttl_duration = 60

#
# Possibly not needed anymore
#

auth_to_orch_token_signing_public_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvvr/3/mHEPLpgsLR3ocLiGrVpVLJ
AZUx4RCDu+VWAZpPi1NaF5XWvkFNFwH+MyLkATh90UEJDe+ayKW6AXFcRQ==
-----END PUBLIC KEY-----
EOT
