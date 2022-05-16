doc_app_api_enabled                = true
ipv_capacity_allowed               = true
ipv_api_enabled                    = true
doc_app_authorisation_client_id    = "authOrchestratorDocApp"
doc_app_authorisation_callback_uri = "https://oidc.staging.account.gov.uk/doc-checking-app-callback"
ipv_authorisation_client_id        = "authOrchestrator"
ipv_authorisation_uri              = "https://staging-di-ipv-core-front.london.cloudapps.digital/oauth2/authorize"
ipv_authorisation_callback_uri     = "https://oidc.staging.account.gov.uk/ipv-callback"
ipv_audience                       = "https://staging-di-ipv-core-front.london.cloudapps.digital"
ipv_backend_uri                    = "https://18zwbqzm0k.execute-api.eu-west-2.amazonaws.com/staging"
ipv_domain                         = "https://identity.staging.account.gov.uk"
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
