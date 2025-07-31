shared_state_bucket = "di-auth-staging-tfstate"

# FMS
frontend_api_fms_tag_value = "authfrontendstaging"

# Auth new strategic account
auth_new_account_id = "851725205974"

# App-specific
internal_sector_uri  = "https://identity.staging.account.gov.uk"
test_clients_enabled = true

orch_redirect_uri                       = "https://oidc.staging.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled      = true
lockout_duration                        = 7200
reduced_lockout_duration                = 900
incorrect_password_lockout_count_ttl    = 7200
support_account_creation_count_ttl      = true
call_ticf_cri                           = true
ticf_cri_service_call_timeout           = 10000
support_reauth_signout_enabled          = true
authentication_attempts_service_enabled = true

## AUTH to IPV reverification
## auth only
ipv_auth_authorize_callback_uri = "https://signin.staging.account.gov.uk/ipv/callback/authorize"
ipv_auth_authorize_client_id    = "auth"

orch_account_id                                    = "590183975515"
is_orch_stubbed                                    = false
orch_environment                                   = "staging"
orch_session_table_encryption_key_arn              = "arn:aws:kms:eu-west-2:590183975515:key/156f87e0-001a-4ae8-a6c1-23f8f68b6e84"
orch_client_session_table_encryption_key_arn       = "arn:aws:kms:eu-west-2:590183975515:key/b94d81a1-a41f-4e61-859c-87dcacb32e51"
orch_identity_credentials_table_encryption_key_arn = "arn:aws:kms:eu-west-2:590183975515:key/d0bdb864-8478-4411-a44a-a4232fc97cf3"
cmk_for_back_channel_logout_enabled                = true

contra_state_bucket = "di-auth-staging-tfstate"

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

reauth_enter_email_count_ttl                = 300
reauth_enter_password_count_ttl             = 300
reauth_enter_sms_code_count_ttl             = 300
reauth_enter_auth_app_code_count_ttl        = 300
ipv_capacity_allowed                        = true
ipv_api_enabled                             = true
doc_app_authorisation_client_id             = "authOrchestratorDocApp"
doc_app_authorisation_uri                   = "https://www.review-b.staging.account.gov.uk/dca/oauth2/authorize"
doc_app_backend_uri                         = "https://api-backend-api.review-b.staging.account.gov.uk"
doc_app_domain                              = "https://api.review-b.staging.account.gov.uk"
doc_app_aud                                 = "https://www.review-b.staging.account.gov.uk"
doc_app_new_aud_claim_enabled               = true
doc_app_authorisation_callback_uri          = "https://oidc.staging.account.gov.uk/doc-app-callback"
doc_app_cri_data_endpoint                   = "userinfo"
doc_app_jwks_endpoint                       = "https://api-backend-api.review-b.staging.account.gov.uk/.well-known/jwks.json"
ipv_authorisation_client_id                 = "authOrchestrator"
ipv_authorisation_uri                       = "https://identity.staging.account.gov.uk/oauth2/authorize"
ipv_authorisation_callback_uri              = "https://oidc.staging.account.gov.uk/ipv-callback"
ipv_audience                                = "https://identity.staging.account.gov.uk"
evcs_audience                               = "https://credential-store.staging.account.gov.uk"
auth_issuer_claim_for_evcs                  = "https://signin.staging.account.gov.uk"
ipv_backend_uri                             = "https://api.identity.staging.account.gov.uk"
spot_enabled                                = true
doc_app_cri_data_v2_endpoint                = "userinfo/v2"
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true
account_intervention_service_abort_on_error = true
## account_intervention_service_uri is stored in AWS Secrets Manager and populated using read_secrets.sh
send_storage_token_to_ipv_enabled = true
ipv_auth_public_encryption_key    = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyB5V0Tc9KEV5/zGUHLu0
ZVX0xbDhCyaNwWjJILV0pJE+HmAUc8Azc42MY9mAm0D3LYF8PcWsBa1cIgJF6z7j
LoM43PR/BZafvYeW7GwIun+pugSQO5ljKzUId42ydh0ynwEXJEoMQd3p4e/EF4Ut
yGCV108TgoqDvD50dtqNOw1wBsfbq4rUaRTxhpJLIo8tujmGpf1YVWymQEk+FlyN
LlZL4UE/eEyp+qztIsVXJfyhcC/ezrr5e0FnZ1U0iJavhdmBqmIaLi3SjNawNdEQ
RWDJd2Fit4x9bFIqpZKqc1pGLu39UEaHLzRgi0hVDQhG5A7LpErOMjWquS2lmkwa
3wIDAQAB
-----END PUBLIC KEY-----
EOT

## The IPV public encrypting key that is specific to auth.
## Note: ipv_auth_public_encryption_key, above, is owned and used by orchestration.
auth_frontend_api_to_ipv_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyB5V0Tc9KEV5/zGUHLu0
ZVX0xbDhCyaNwWjJILV0pJE+HmAUc8Azc42MY9mAm0D3LYF8PcWsBa1cIgJF6z7j
LoM43PR/BZafvYeW7GwIun+pugSQO5ljKzUId42ydh0ynwEXJEoMQd3p4e/EF4Ut
yGCV108TgoqDvD50dtqNOw1wBsfbq4rUaRTxhpJLIo8tujmGpf1YVWymQEk+FlyN
LlZL4UE/eEyp+qztIsVXJfyhcC/ezrr5e0FnZ1U0iJavhdmBqmIaLi3SjNawNdEQ
RWDJd2Fit4x9bFIqpZKqc1pGLu39UEaHLzRgi0hVDQhG5A7LpErOMjWquS2lmkwa
3wIDAQAB
-----END PUBLIC KEY-----
EOT

auth_frontend_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzZGTSE8TLLtQjdmD6SiF
SKbfv63JPCV+acPLQc4MjAKK7yT/QhERkemky+oPBIqCJgUq1gmOzdCAje/QEFlD
qwry65oEaUBlWmGlNTPBnUzy/d6mYMfZObsr+yI1HszZE193ABAwtPttCFhFZWov
+rF2Oc9dmiAKXuT0whbOXaj1+751w5qJpsMWgHj91at9gdOZ31huoxnLkuAK/rus
wEBMjmuOzy5osorLg9RCJQVN91Bp932vQS7hXirDpfBhCuQfYQMjFXv4MhCKnk42
pi0FWWzbnn9UcbdcS/Sl5UeuTyCQ+MrunV/XGjIrPMWaFUIQomX1+pCMHkthbQ0J
AQIDAQAB
-----END PUBLIC KEY-----
EOT

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

  reset-password = {
    memory          = 1024
    concurrency     = 2
    max_concurrency = 10
    scaling_trigger = 0.5
  }

  reset-password-request = {
    memory          = 1024
    concurrency     = 2
    max_concurrency = 10
    scaling_trigger = 0.5
  }

  reverification-result = {
    memory          = 1536
    concurrency     = 1
    max_concurrency = 10
    scaling_trigger = 0.6
  }
}
lambda_max_concurrency        = 10
lambda_min_concurrency        = 3
use_strongly_consistent_reads = true

ipv_jwks_call_enabled = true
ipv_jwks_url          = "https://api.identity.staging.account.gov.uk/.well-known/jwks.json"
