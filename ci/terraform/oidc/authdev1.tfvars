shared_state_bucket = "di-auth-development-tfstate"

# Feature Flags
test_clients_enabled                        = true
ipv_api_enabled                             = true
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true
account_intervention_service_abort_on_error = true
send_storage_token_to_ipv_enabled           = true
call_ticf_cri                               = true
ipv_backend_uri                             = "https://ipvstub.signin.authdev1.dev.account.gov.uk"

ipv_authorisation_uri           = "https://ipvstub.signin.authdev1.dev.account.gov.uk/authorize/"
ipv_auth_authorize_callback_uri = "https://signin.authdev1.dev.account.gov.uk/ipv/callback/authorize"
ipv_auth_authorize_client_id    = "authTestClient"
ipv_audience                    = "https://ipvstub.signin.authdev1.dev.account.gov.uk"
evcs_audience                   = "https://credential-store.authdev1.dev.account.gov.uk"
auth_issuer_claim_for_evcs      = "https://signin.authdev1.dev.account.gov.uk"

## The IPV public encrypting key that is specific to auth

auth_frontend_api_to_ipv_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArJ8oZkHs+ReeZcUsIeWm
bwigustlHH8Qlsb/3SAK1wPb2muVRtQPZjF9TGnu8cof9pHdOo1blpvr8NNTKKTW
D+gQRi9NzlPEVWS0Uo7PFNb0CJ4Vzd5Qgrc8GMc35lcgF3UBNFdcLErfr8Mi1/qO
zld/NBsLCgG/lQ/s8uoNv9jBtwKko+vR1OPt4ziGL2+OfOU5W6U8gwGexcpNEANx
95gokzduQTMQUAuOvM/rQMKYGjUqKbiQyB89Y9o3b6SDF32tEkNkyfJ4tiEYJmrq
V3/gq1/DRbG7neNvo/klcojjdmBsrn7eIb310NDJhAvS3CPcWnrcYRFZMdkBNikY
9QIDAQAB
-----END PUBLIC KEY-----
EOT

auth_frontend_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs0gyWacjheeaMslIDBdf
4ljBMyrEzAeJW+ZyvGZlV6KhPPCz6lMx8knb/ar1LqkqX1M2hh1qS+ijYtzz4cCE
MP/YWuvIL3CkFEUlw1ITwg6TDH9ixFeFHG0K4keHmmAHms5N4zuUKwZWHUgo6nDt
LM3o5PIvdz57A1ewtkzLizLBHIhTMImXeHzFyEDH7LufROfJH9lZ079r2sNzfKSm
xhgnWpMKrXtYUkYR/+vmvCJcR4okWS5WK9QKh2PUw+fXBRxnaf09sRvvgh2x/I9A
wxACgcz//hhZ9O1h3Kt6BTyvhqZ00FwO//2bdosdX9kjCC+bRCwlUToIY0CmzOFO
kwIDAQAB
-----END PUBLIC KEY-----
EOT

auth_to_orch_token_signing_public_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgim+WxL5qzcUSboPEiAcbu+DBn8v
PirNO+f1KP1HGi7oYdoiFgVXejoUmpxKXeQRtOF6PgTBkrRMzmI51YFLDQ==
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
reauth_enter_auth_app_code_count_ttl      = 120
reauth_enter_sms_code_count_ttl           = 120

# Auth new strategic account
auth_new_account_id = "975050272416"

orch_account_id = "816047645251"
is_orch_stubbed = true

contra_state_bucket = "di-auth-development-tfstate"

orch_redirect_uri = "https://oidc.authdev1.dev.account.gov.uk/orchestration-redirect"

authorize_protected_subnet_enabled = true

oidc_cloudfront_enabled = false

support_reauth_signout_enabled          = true
authentication_attempts_service_enabled = true
use_strongly_consistent_reads           = true
