notify_template_map = {
  VERIFY_EMAIL_TEMPLATE_ID                               = "09f29c9a-3f34-4a56-88f5-8197aede7f85"
  VERIFY_PHONE_NUMBER_TEMPLATE_ID                        = "8babad52-0e2e-443a-8a5a-c296dc1696cc"
  MFA_SMS_TEMPLATE_ID                                    = "31e48dbf-6db6-4864-9710-081b72746698"
  PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID                = "c5a6a8d6-0a45-4496-bec8-37167fc6ecaa"
  ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID               = "99580afe-9d3f-4ed1-816d-3b583a7b9167"
  RESET_PASSWORD_WITH_CODE_TEMPLATE_ID                   = "4f76b165-8935-49fe-8ba8-8ca62a1fe723"
  PASSWORD_RESET_CONFIRMATION_SMS_TEMPLATE_ID            = "86a27ea9-e8ac-423f-a444-b2751e165887"
  VERIFY_CHANGE_HOW_GET_SECURITY_CODES_TEMPLATE_ID       = "49b3aea6-9a67-4ef4-af08-3297c1cce82c"
  CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION_TEMPLATE_ID = "d253a170-8144-4471-b339-c35965c9298a"
}

custom_doc_app_claim_enabled = true
doc_app_cri_data_endpoint    = "userinfo"
doc_app_cri_data_v2_endpoint = "userinfo/v2"

doc_app_backend_uri                = "https://api-backend-api.review-b.account.gov.uk"
doc_app_domain                     = "https://api.review-b.account.gov.uk"
doc_app_aud                        = "https://www.review-b.account.gov.uk"
doc_app_new_aud_claim_enabled      = true
doc_app_authorisation_client_id    = "authOrchestratorDocApp"
doc_app_authorisation_callback_uri = "https://oidc.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri          = "https://www.review-b.account.gov.uk/dca/oauth2/authorize"
doc_app_jwks_endpoint              = "https://api-backend-api.review-b.account.gov.uk/.well-known/jwks.json"
doc_app_encryption_key_id          = "7958938d-eea0-4e6d-9ea1-ec0b9d421f77"

cloudwatch_log_retention                    = 30
client_registry_api_enabled                 = false
spot_enabled                                = true
ipv_api_enabled                             = true
ipv_capacity_allowed                        = true
ipv_no_session_response_enabled             = true
ipv_authorisation_uri                       = "https://identity.account.gov.uk/oauth2/authorize"
ipv_authorisation_callback_uri              = "https://oidc.account.gov.uk/ipv-callback"
ipv_backend_uri                             = "https://api.identity.account.gov.uk"
ipv_audience                                = "https://identity.account.gov.uk"
internal_sector_uri                         = "https://identity.account.gov.uk"
ipv_authorisation_client_id                 = "authOrchestrator"
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true
ipv_auth_public_encryption_key              = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4K/6GH//FQSD6Yk/5nKY
zRCwrYcQy7wGHH2cZ7EXo/9+SNRcbQlzd+NVTplIk9x7+t7g8U36z/I8CM/woGgJ
zM8DNREecxH/4YEYKOqbqHSnK7iICJ18Wfb+mNr20Dt+Ik1oQja6aKPqIj4Jl4WW
0vHMhDfUNP/iOi3zhNJsTZwYjVQWqLzmWfAqO/61d2XbLDIgubKqAtTFWnxeXuBU
VZAbq03qmvzyekRUvZtck7JuQUa9mj2gJC0YPLoLDM+j0QDGWrPnDA2L2VmmF1wn
rbeA0zSUxxfdffFH/L0cTgzdTQtv6iGQrkfHnTTk1TQe0+wxJEQz5FlcXYl6qSrh
swIDAQAB
-----END PUBLIC KEY-----
EOT

orch_client_id = "orchestrationAuth"

auth_frontend_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAppKCOhyLiKs5QTB1L+XK
Tgs9kosxma0PuagvNkP+UEPd0KumWc4sWlYUzR1D1aPX8AGDSQ1awOIb7PhlE5Ss
5LilounpT9Pi+FvHFlGKgQzRO63j9CRXzYxhgHGpruzAAKUQ+6D0cuOdao3YF0zz
RmaMSdHB4HsNhxV5DHY+2Rr7GeEfl6lQB8EHTAQzoagsIxihxNieUIGhHcegbCv6
X5aV67lUEbjjfvGu888GL8qJakOPNoIn/pMBB5LIKVxbyoCB9nfFZ5fPFxBpLdvy
p0qsf76XAFuA3nhupIqkXl8jOIDN3U79V1kAgyS8uoilhhblqAtCoJElEiDYQh1M
NQIDAQAB
-----END PUBLIC KEY-----
EOT

performance_tuning = {
  register = {
    memory          = 1536
    concurrency     = 0
    max_concurrency = 0
    scaling_trigger = 0
  }

  update = {
    memory          = 1536
    concurrency     = 0
    max_concurrency = 0
    scaling_trigger = 0
  }

  reset-password = {
    memory          = 1536
    concurrency     = 2
    max_concurrency = 10
    scaling_trigger = 0.5
  }

  reset-password-request = {
    memory          = 1536
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

shared_state_bucket = "digital-identity-prod-tfstate"
