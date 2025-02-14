shared_state_bucket = "di-auth-development-tfstate"

# App-specific
test_clients_enabled                        = true
ipv_api_enabled                             = true
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true
account_intervention_service_abort_on_error = true
send_storage_token_to_ipv_enabled           = true
call_ticf_cri                               = true
ipv_backend_uri                             = "https://ipvstub.signin.authdev2.dev.account.gov.uk"

ipv_authorisation_uri           = "https://ipvstub.signin.authdev2.dev.account.gov.uk/authorize/"
ipv_auth_authorize_callback_uri = "https://signin.authdev2.dev.account.gov.uk/ipv/callback/authorize"
ipv_auth_authorize_client_id    = "authTestClient"
ipv_audience                    = "https://ipvstub.signin.authdev2.dev.account.gov.uk"
evcs_audience                   = "https://credential-store.authdev2.dev.account.gov.uk"
auth_issuer_claim_for_evcs      = "https://signin.authdev2.dev.account.gov.uk"

## The IPV public encrypting key that is specific to auth

auth_frontend_api_to_ipv_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArOb0Y+6vaIfR7ThOVIKJ
die8s6Db4wifjZW4vnw6x+SOJfSMZTfju9gpN9rgHPkYtkaH8P3cU34Ow1w6nG91
OijyX+u1Q/gzt2lSisQOUSGiK6yB0GEcPuQwqt6QH3o11oX78l3uvdQn0cbV3pAY
Oce8mkg/ruDHRYw7dR+9F+5oDQ8gk25qQzwyoE7rkTxW5UvPH8kmQ4ioc7O1IoFl
MKzhijegD77BqVWK1YRVjwWLGGj/gJQXY6jvEuDVrkMB992Oi0rno+DpCIT0/uZd
6xn7WDx0bLme/nKHVKnWCAbpZ7beIQUaZKn/nSrNUlYIpI6DhMzecJDpNS2JvH8V
RwIDAQAB
-----END PUBLIC KEY-----
EOT

auth_frontend_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlWwvS/QGYHfu8nufIzgo
05G4GEjMHvOXGywV61Inev6+46VF36rAs1+ZtxAhR6D4FFDbyLFhej0Rp/H9PMnk
rwaIoRkZq89BHAX/yklx3EYPkdRhsXjfWocL7ZJP/JgFcNZV/eE2ZOf9O3UmcVGy
DCQMhKDhYX3XFR5mtd2lCHmu9TtONvodQ2zf0REFPJey1X4M3JYWhtW0lm8lxuFM
+wq2LiUkwO6qgTiUcweMzKVNMX55pLajsL9o/wVApm9FiGLB1Ndt4aRT6JIbgG3U
G+6lf+OkwDRht0L31b0vGGzy263wprcxjd/v3bznttaTP8W2ouwh9UdTBWMq+BIB
zwIDAQAB
-----END PUBLIC KEY-----
EOT

auth_to_orch_token_signing_public_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEj8nFPRrn+Pi89gvGHeetF13LQx3e
rd1KO7rlh+7WxC9coRZVLrr6tp+UO/HcHJjAWTh9VhDcx5gVmR/DGKmk2w==
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
reauth_enter_sms_code_count_ttl           = 120
reauth_enter_auth_app_code_count_ttl      = 120


orch_account_id = "816047645251"
is_orch_stubbed = true

contra_state_bucket = "di-auth-development-tfstate"

orch_redirect_uri                  = "https://oidc.authdev2.sandpit.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled = true

oidc_cloudfront_enabled = false

support_reauth_signout_enabled          = true
authentication_attempts_service_enabled = true
