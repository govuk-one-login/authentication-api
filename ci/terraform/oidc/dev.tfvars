shared_state_bucket = "di-auth-development-tfstate"

# FMS
frontend_api_fms_tag_value = "authfrontenddev"

# Auth new strategic account
auth_new_account_id = "975050272416"

# App-specific
test_clients_enabled = true
internal_sector_uri  = "https://identity.dev.account.gov.uk"
call_ticf_cri        = true
ipv_backend_uri      = "https://ipvstub.signin.dev.account.gov.uk"

## AUTH to IPV reverification
## Shared with orch
ipv_authorisation_uri = "https://ipvstub.signin.dev.account.gov.uk/authorize/"
## auth only
ipv_auth_authorize_callback_uri = "https://signin.dev.account.gov.uk/ipv/callback/authorize"
ipv_auth_authorize_client_id    = "authTestClient"

## lockout config
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

orch_redirect_uri                  = "https://oidc.dev.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled = true

orch_account_id = "816047645251"
is_orch_stubbed = true

contra_state_bucket = "di-auth-development-tfstate"

oidc_cloudfront_enabled = false

doc_app_cri_data_endpoint                   = "credentials/issue"
doc_app_backend_uri                         = "https://dcmaw-cri.dev.stubs.account.gov.uk"
doc_app_domain                              = "https://dcmaw-cri.dev.stubs.account.gov.uk"
doc_app_authorisation_client_id             = "orch-dev"
doc_app_authorisation_callback_uri          = "https://oidc.dev.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri                   = "https://dcmaw-cri.dev.stubs.account.gov.uk/authorize"
doc_app_jwks_endpoint                       = "https://dcmaw-cri.dev.stubs.account.gov.uk/.well-known/jwks.json"
doc_app_aud                                 = "https://dcmaw-cri.dev.stubs.account.gov.uk"
doc_app_new_aud_claim_enabled               = true
doc_app_encryption_key_id                   = ""
spot_enabled                                = false
custom_doc_app_claim_enabled                = true
ipv_audience                                = "https://ipvstub.signin.dev.account.gov.uk"
doc_app_cri_data_v2_endpoint                = "credentials/issue"
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true
# account_intervention_service_uri is stored in AWS Secrets Manager and populated using read_secrets.sh
account_intervention_service_abort_on_error = true
send_storage_token_to_ipv_enabled           = true
authentication_attempts_service_enabled     = true
auth_frontend_public_encryption_key         = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0PcOHuVXOuexYZmpOlCo
vFcGfezObHnnVTTfnCrS5TBmAEC9JNwH/YFmE/zx84I1dy5fEjll+2GIe8Hcue+W
ubQMToFaAAeaqowqjgJYIPjgTubJ+baAP7+6GFPBWkk+LntBRQaoF7YkICT6im9h
JTrFb5KxyDNT/j4SCCXlkMTzqmeMVM59NM66MSS7OXsUny9GinG6xhDovUswvU99
N7GtGZBYIDmG6IrT/rS9ZosBLeLqCvRAfaYjq0/2EKHcudyeYjPDkkGpBNt7vXJJ
A+Ud3Nx8MmuKS3kb8NoDhQJxKxg7lgjAj+Lhb9xr+Y074hdTs5ju2Jx2tmP1y9vl
RwIDAQAB
-----END PUBLIC KEY-----
EOT

# The IPV public encrypting key that is specific to auth.
auth_frontend_api_to_ipv_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApuWFONCQ572vESMrN0Wj
+Q3J866fk0x0GF1TaLJDk7X7RdooUAQo95b1e1Qg+UFHR6P9+Ay1u7xdjmud4w/3
zIHQzXejRwy/RruymdimvvJAKfh1nDsQUygssGoCFWcCaq7ywMHx/kKIy1GBh2vY
wyOCs1IvK8C8hTEy7hvVQ4vEZu17o+EBgbwX5398DebXXB6SNCKqDZnmLYDfmhGd
beQWJg5UIvT2fRNBoevG+N4kZKmjpyANmOKY/J/lYzoHguXhACTFkPzxCkbSaZC/
eUfXfBO9PWUTtwaxXrp3pjO421dWvuXfIOrV1YVmUhIpH193j9Roe4C3CGh18urF
sQIDAQAB
-----END PUBLIC KEY-----
EOT

evcs_audience              = "https://credential-store.dev.account.gov.uk"
auth_issuer_claim_for_evcs = "https://signin.dev.account.gov.uk"

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
