doc_app_api_enabled                = true
ipv_capacity_allowed               = true
ipv_api_enabled                    = true
doc_app_authorisation_client_id    = "authOrchestratorDocApp"
doc_app_authorisation_callback_uri = "https://oidc.staging.account.gov.uk/doc-app-callback"
doc_app_encryption_key_id          = "ca6d5930-77a6-41a4-8192-125df996c084"
doc_app_signing_key_id             = "991d4f12-0367-4eb6-b166-607565a3e2d8"
doc_app_jwks_endpoint              = "https://backend-api-jwks-staging.s3.eu-west-2.amazonaws.com/.well-known/jwks.json"
ipv_authorisation_client_id        = "authOrchestrator"
ipv_authorisation_uri              = "https://identity.staging.account.gov.uk/oauth2/authorize"
ipv_authorisation_callback_uri     = "https://oidc.staging.account.gov.uk/ipv-callback"
ipv_audience                       = "https://identity.staging.account.gov.uk"
ipv_backend_uri                    = "https://api.identity.staging.account.gov.uk"
ipv_sector                         = "https://identity.staging.account.gov.uk"
spot_enabled                       = true
identity_trace_logging_enabled     = true
ipv_auth_public_encryption_key     = <<-EOT
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
doc_app_auth_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAudZq3RAtd6me99lfWd8N
AfOIo5rfkt0uCOMtTqHlYVLbjIBeLRvSg1Aq55mSFKbdJ+DE4wFN9PyGZVpH266C
2DVSOVI0ETfmPP2rVyG9FXwJqGsWYEn7XMqznFPlxi9IjeqOjhybLlaZKdm6VCpO
KEoQViR4Cm73eax1KDztlmOncypB1o8WIEte3SvFK97Ar3KTJgaS1PsmgXttx6AP
Q3D0/fQcE0Hp/swIgPsO9gYxhEdv3M+dxO07OJ+/X396bg+uZ7/J84hTz/uIXASy
bJ5G58qyvEL0h3BMEBayDN1cT3/Q7NU3jkaa1ODynLjkvXEtlccgsrAa2he7OQUY
ZQIDAQAB
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
keep_lambdas_warm      = false
endpoint_memory_size   = 1024
scaling_trigger        = 0.6
