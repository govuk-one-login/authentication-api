shared_state_bucket = "di-auth-development-tfstate"
contra_state_bucket = "di-auth-development-tfstate"

# FMS
frontend_api_fms_tag_value = "authfrontendsp"


# App-specific
test_clients_enabled                        = true
ipv_api_enabled                             = true
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true
account_intervention_service_abort_on_error = true
send_storage_token_to_ipv_enabled           = true
call_ticf_cri                               = true
support_reauth_signout_enabled              = true
authentication_attempts_service_enabled     = true

ipv_backend_uri = "https://ipvstub.signin.authdev3.dev.account.gov.uk"

ipv_authorisation_uri           = "https://ipvstub.signin.authdev3.dev.account.gov.uk/authorize/"
ipv_auth_authorize_callback_uri = "https://signin.authdev3.dev.account.gov.uk/ipv/callback/authorize"
ipv_auth_authorize_client_id    = "authTestClient"
ipv_audience                    = "https://ipvstub.signin.authdev3.dev.account.gov.uk"
evcs_audience                   = "https://credential-store.authdev3.dev.account.gov.uk"
auth_issuer_claim_for_evcs      = "https://signin.authdev3.dev.account.gov.uk"
internal_sector_uri             = "https://identity.authdev3.dev.account.gov.uk"

auth_frontend_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuCRGXGEbDsWA/hW1vZUm
GxTfr1u763wGQT03m3pvBUgKV3Mbs/+fJl2VJoAJboqDxn3lQVhP9r/Xj6/L7T69
czzKpojyzs6VtiJ+iCLDD2lX0hFZPToQ6fjP/gb8rHwfCqQE0A/rSEaM4GSh7xL/
WL8/7BedqkR4HpBqSbkMSEUDCTmImVThRyTucTuMCoiLyqFdEIDbAlY3emHDjxJC
/Oo36f0G8/wr1WcWqd6EzBJIpSGKafoDk8mVyz8uHQGXHR+ZRTazImMNrqnwIFVD
tRVhSZvhgdyjcixYvMnmkPdSdz+9W5ctwhnN5M1vaNY6aRZBzDdQLsPXOrj6HNiu
7QIDAQAB
-----END PUBLIC KEY-----
EOT

auth_to_orch_token_signing_public_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDCSU8Ep347sdBs17gbT4YxeLgFpK
IEoUCCVAueB4V8ELA/pCrui6xT5+oD77XrMyKT0OqIHH5Wh9xSoyMAgx0g==
-----END PUBLIC KEY-----
EOT

enable_api_gateway_execution_request_tracing = true
spot_enabled                                 = false

## lockout config
lockout_duration                          = 600
reduced_lockout_duration                  = 300
incorrect_password_lockout_count_ttl      = 600
lockout_count_ttl                         = 600
otp_code_ttl_duration                     = 600
email_acct_creation_otp_code_ttl_duration = 600
reauth_enter_email_count_ttl              = 120
reauth_enter_password_count_ttl           = 120
reauth_enter_auth_app_code_count_ttl      = 120
reauth_enter_sms_code_count_ttl           = 120


orch_frontend_api_gateway_integration_enabled = false

orch_redirect_uri = "https://oidc.authdev3.dev.account.gov.uk/orchestration-redirect"

authorize_protected_subnet_enabled = true

use_strongly_consistent_reads = true

# disaling OIDC temporarly
oidc_cloudfront_enabled = false


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
orch_auth_code_enabled               = true
orch_userinfo_enabled                = true
orch_storage_token_jwk_enabled       = true
orch_ipv_jwks_enabled                = true

orch_account_id                                    = "816047645251"
is_orch_stubbed                                    = false
orch_environment                                   = "dev"
orch_session_table_encryption_key_arn              = "arn:aws:kms:eu-west-2:816047645251:key/645669ba-b288-4b63-bfe1-9d8bde9956ec"
orch_client_session_table_encryption_key_arn       = "arn:aws:kms:eu-west-2:816047645251:key/4cd7c551-128f-4579-99c2-a7f1bff64fb7"
orch_identity_credentials_table_encryption_key_arn = "arn:aws:kms:eu-west-2:816047645251:key/590f841e-3eec-45f1-a9bc-4b32b2edece4"
orch_client_registry_table_encryption_key_arn      = "arn:aws:kms:eu-west-2:816047645251:key/97c19476-82ba-433f-8500-981857e7367e"

cmk_for_back_channel_logout_enabled = true

auth_new_account_id = "653994557586"
