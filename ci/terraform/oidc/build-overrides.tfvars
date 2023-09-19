doc_app_api_enabled                 = true
doc_app_cri_data_endpoint           = "credentials/issue"
doc_app_backend_uri                 = "https://build-doc-app-cri-stub.london.cloudapps.digital"
doc_app_domain                      = "https://build-doc-app-cri-stub.london.cloudapps.digital"
doc_app_authorisation_client_id     = "authOrchestratorDocApp"
doc_app_authorisation_callback_uri  = "https://oidc.build.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri           = "https://build-doc-app-cri-stub.london.cloudapps.digital/authorize"
doc_app_jwks_endpoint               = "https://build-doc-app-cri-stub.london.cloudapps.digital/.well-known/jwks.json"
doc_app_encryption_key_id           = "7788bc975abd44e8b4fd7646d08ea9428476e37bff3e4365804b41cc29f8ef21"
spot_enabled                        = false
language_cy_enabled                 = true
internal_sector_uri                 = "https://identity.build.account.gov.uk"
extended_feature_flags_enabled      = true
support_auth_orch_split             = false
custom_doc_app_claim_enabled        = true
ipv_no_session_response_enabled     = true
doc_app_cri_data_v2_endpoint        = "credentials/issue"
doc_app_use_cri_data_v2_endpoint    = true
orch_client_id                      = "orchestrationAuth"
auth_frontend_public_encryption_key = <<-EOT
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

blocked_email_duration = 30
otp_code_ttl_duration  = 120

logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]

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
lambda_max_concurrency = 0
lambda_min_concurrency = 1
endpoint_memory_size   = 1024
scaling_trigger        = 0.6
