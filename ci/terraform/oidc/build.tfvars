shared_state_bucket = "digital-identity-dev-tfstate"

# FMS
frontend_api_fms_tag_value = "authfrontendbuild"

# Auth new strategic account
auth_new_account_id = "058264536367"

# App-specific
ipv_backend_uri = "https://ipvstub.signin.build.account.gov.uk"

# AUTH to IPV reverification
# Shared with orch
ipv_authorisation_uri = "https://ipvstub.signin.build.account.gov.uk/authorize/"
# auth only
ipv_auth_authorize_callback_uri = "https://signin.build.account.gov.uk/ipv/callback/authorize"
ipv_auth_authorize_client_id    = "authTestClient"
ipv_audience                    = "https://ipvstub.signin.build.account.gov.uk"

internal_sector_uri  = "https://identity.build.account.gov.uk"
test_clients_enabled = true
ipv_api_enabled      = true
call_ticf_cri        = true

## lockout config
lockout_duration                          = 60
reduced_lockout_duration                  = 30
incorrect_password_lockout_count_ttl      = 60
lockout_count_ttl                         = 60
otp_code_ttl_duration                     = 60
account_creation_lockout_count_ttl        = 60
support_account_creation_count_ttl        = true
email_acct_creation_otp_code_ttl_duration = 60


auth_to_orch_token_signing_public_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvvr/3/mHEPLpgsLR3ocLiGrVpVLJ
AZUx4RCDu+VWAZpPi1NaF5XWvkFNFwH+MyLkATh90UEJDe+ayKW6AXFcRQ==
-----END PUBLIC KEY-----
EOT

orch_redirect_uri                  = "https://oidc.build.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled = true

contra_state_bucket = "digital-identity-dev-tfstate"

orch_account_id                                    = "767397776536"
is_orch_stubbed                                    = false
orch_environment                                   = "build"
orch_session_table_encryption_key_arn              = "arn:aws:kms:eu-west-2:767397776536:key/b7cb6340-0d22-4b6a-8702-b5ec17d4f979"
orch_client_session_table_encryption_key_arn       = "arn:aws:kms:eu-west-2:767397776536:key/7a1d86fe-1ca0-499c-95e9-ee8593a850f9"
orch_identity_credentials_table_encryption_key_arn = "arn:aws:kms:eu-west-2:767397776536:key/e284a04a-bac2-42b0-b723-ef0d32722ad5"

orch_storage_token_jwk_enabled              = true
orch_openid_configuration_enabled           = true
orch_jwks_enabled                           = true
orch_register_enabled                       = true
orch_authorisation_enabled                  = true
orch_logout_enabled                         = true
orch_token_enabled                          = true
orch_userinfo_enabled                       = true
orch_auth_code_enabled                      = true
orch_authentication_callback_enabled        = true
orch_doc_app_callback_enabled               = true
orch_ipv_callback_enabled                   = true
auth_spot_response_disabled                 = true
orch_ipv_jwks_enabled                       = true
doc_app_cri_data_endpoint                   = "credentials/issue"
doc_app_backend_uri                         = "https://dcmaw-cri.build.stubs.account.gov.uk"
doc_app_domain                              = "https://dcmaw-cri.build.stubs.account.gov.uk"
doc_app_authorisation_client_id             = "orch-build"
doc_app_authorisation_callback_uri          = "https://oidc.build.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri                   = "https://dcmaw-cri.build.stubs.account.gov.uk/authorize"
doc_app_jwks_endpoint                       = "https://dcmaw-cri.build.stubs.account.gov.uk/.well-known/jwks.json"
doc_app_aud                                 = "https://dcmaw-cri.build.stubs.account.gov.uk"
doc_app_new_aud_claim_enabled               = true
doc_app_encryption_key_id                   = "dcmaw-cri-stubs-build-INqHBvMYWmNodklvbpTCgf1DS10Fv5ic4_8LdoBNjAw"
spot_enabled                                = false
custom_doc_app_claim_enabled                = true
doc_app_cri_data_v2_endpoint                = "credentials/issue"
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true
## account_intervention_service_uri is stored in AWS Secrets Manager and populated using read_secrets.sh
support_reauth_signout_enabled          = true
authentication_attempts_service_enabled = true
send_storage_token_to_ipv_enabled       = true
auth_frontend_public_encryption_key     = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApLJWOHz7uHLinSJr8XM0
fhyq0aLm8HP06lCT7csGUoRav2xybsCsypufvJHbuD5SLkg25/VGFt21KH2g60u8
6mV7ULLG/m4hvAiXbwSGdcRTToPS+UULX3YDnDXZHvd+3ypane82+XLjVZ9B2V0i
1MGCJ7kiRurXCuE+9Kx/MQYBCqhz/OwHlCe3FJZXKvgnqqpO5ZtyjrxDJSZJpxbi
KsVnLksPKV10Z0/XvpJ6oHtOjseetk8TRdekRWBvqCX5MqLjdi1TfiaDu2Tjg2N0
dqhoDR3/THktb4KThc+U5EOWCWpH4OIAetYtjFChnkR8kU05Ol9zfdR08uO0RxMk
1wIDAQAB
-----END PUBLIC KEY-----
EOT

# The IPV public encrypting key that is specific to auth.
auth_frontend_api_to_ipv_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo9DGrlCJ1qrrXzeiSeLr
6rzPmsIiF6hGxl8B4axJkBsfZWldFpPw1CvX/sP1FtY5fdVdUG7U1uMObcmE43tQ
EiBv7vPWZ9wRI7knjc8ncrGmzhU1eeWyrhDIuhnJFm2iCldigLQu7DfCJMWAtsk2
g/NMKsC9qYmyHD9QIpQTVt9/HjfzYXFTXtSettNlku2Xi5FjtCpdLEXOMezhRXjF
imObuMzdLZYryP17mr2OJy9d+227FCexPG6UYOgH21RtOE9gxC2iLGMdqEmfTQt/
G+lrdOD+OMl6qTVg+zJqG3amdPFnb4Vmnp8rOVnio30PFd71JxSqQsED8jjUW6KK
FQIDAQAB
-----END PUBLIC KEY-----
EOT

evcs_audience              = "https://credential-store.build.account.gov.uk"
auth_issuer_claim_for_evcs = "https://signin.build.account.gov.uk"

# Logging
logging_endpoint_arns = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]

# Sizing
performance_tuning = {
  register = {
    memory          = 512
    concurrency     = 0
    max_concurrency = 0
    scaling_trigger = 0
  }

  update = {
    memory          = 512
    concurrency     = 0
    max_concurrency = 0
    scaling_trigger = 0
  }
}
lambda_min_concurrency        = 1
use_strongly_consistent_reads = true
