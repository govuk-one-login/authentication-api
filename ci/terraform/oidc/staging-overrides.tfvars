custom_doc_app_claim_enabled                = true
ipv_capacity_allowed                        = true
ipv_api_enabled                             = true
doc_app_authorisation_client_id             = "authOrchestratorDocApp"
doc_app_authorisation_uri                   = "https://www.review-b.staging.account.gov.uk/dca/oauth2/authorize"
doc_app_backend_uri                         = "https://api-backend-api.review-b.staging.account.gov.uk"
doc_app_domain                              = "https://api.review-b.staging.account.gov.uk"
doc_app_aud                                 = "https://www.review-b.staging.account.gov.uk"
doc_app_new_aud_claim_enabled               = true
doc_app_authorisation_callback_uri          = "https://oidc.staging.account.gov.uk/doc-app-callback"
doc_app_encryption_key_id                   = "ca6d5930-77a6-41a4-8192-125df996c084"
doc_app_cri_data_endpoint                   = "userinfo"
doc_app_jwks_endpoint                       = "https://api-backend-api.review-b.staging.account.gov.uk/.well-known/jwks.json"
ipv_authorisation_client_id                 = "authOrchestrator"
ipv_authorisation_callback_uri              = "https://oidc.staging.account.gov.uk/ipv-callback"
internal_sector_uri                         = "https://identity.staging.account.gov.uk"
spot_enabled                                = true
test_clients_enabled                        = "true"
doc_app_cri_data_v2_endpoint                = "userinfo/v2"
orch_client_id                              = "orchestrationAuth"
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true
account_intervention_service_abort_on_error = true
# account_intervention_service_uri is stored in AWS Secrets Manager and populated using read_secrets.sh
send_storage_token_to_ipv_enabled   = true
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

#
# Shared with Orchestration
#
ipv_audience    = "https://identity.staging.account.gov.uk"
ipv_backend_uri = "https://api.identity.staging.account.gov.uk"

#
# Auth specific overrides
#
auth_issuer_claim_for_ipv       = "auth"
auth_issuer_claim               = "https://signin.staging.account.gov.uk"
evcs_audience                   = "https://credential-store.staging.account.gov.uk"
ipv_auth_authorize_callback_uri = "https://signin.staging.account.gov.uk/ipv/callback/authorize"
ipv_auth_authorize_client_id    = "auth"

# The IPV public encrypting key that is specific to auth.
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
lambda_max_concurrency = 10
lambda_min_concurrency = 3
endpoint_memory_size   = 1536
scaling_trigger        = 0.6

logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]

shared_state_bucket = "di-auth-staging-tfstate"

#
# Possibly not needed anymore
#

# Note: this is owned (and possibly) used by orchestration.
ipv_auth_public_encryption_key = <<-EOT
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
