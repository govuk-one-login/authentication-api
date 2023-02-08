doc_app_api_enabled                = true
ipv_capacity_allowed               = true
ipv_api_enabled                    = true
doc_app_authorisation_client_id    = "authOrchestratorDocApp"
doc_app_authorisation_uri          = "https://www.review-b.staging.account.gov.uk/dca/oauth2/authorize"
doc_app_backend_uri                = "https://api-backend-api.review-b.staging.account.gov.uk"
doc_app_domain                     = "https://api.review-b.staging.account.gov.uk"
doc_app_authorisation_callback_uri = "https://oidc.staging.account.gov.uk/doc-app-callback"
doc_app_encryption_key_id          = "ca6d5930-77a6-41a4-8192-125df996c084"
doc_app_cri_data_endpoint          = "userinfo"
doc_app_jwks_endpoint              = "https://api-backend-api.review-b.staging.account.gov.uk/.well-known/jwks.json"
ipv_authorisation_client_id        = "authOrchestrator"
ipv_authorisation_uri              = "https://identity.staging.account.gov.uk/oauth2/authorize"
ipv_authorisation_callback_uri     = "https://oidc.staging.account.gov.uk/ipv-callback"
ipv_audience                       = "https://identity.staging.account.gov.uk"
ipv_backend_uri                    = "https://api.identity.staging.account.gov.uk"
internal_sector_uri                = "https://identity.staging.account.gov.uk"
spot_enabled                       = true
identity_trace_logging_enabled     = true
language_cy_enabled                = true
extended_feature_flags_enabled     = true
test_clients_enabled               = "true"

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
lambda_max_concurrency = 3
lambda_min_concurrency = 1
endpoint_memory_size   = 1024
scaling_trigger        = 0.6

logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]

notify_template_map = {
  VERIFY_EMAIL_TEMPLATE_ID                 = "09f29c9a-3f34-4a56-88f5-8197aede7f85"
  VERIFY_PHONE_NUMBER_TEMPLATE_ID          = "8babad52-0e2e-443a-8a5a-c296dc1696cc"
  MFA_SMS_TEMPLATE_ID                      = "31e48dbf-6db6-4864-9710-081b72746698"
  PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID  = "c5a6a8d6-0a45-4496-bec8-37167fc6ecaa"
  ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID = "99580afe-9d3f-4ed1-816d-3b583a7b9167"
  RESET_PASSWORD_WITH_CODE_TEMPLATE_ID     = "4f76b165-8935-49fe-8ba8-8ca62a1fe723"
}