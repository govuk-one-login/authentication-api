environment                                 = "authdev1"
dns_state_bucket                            = null
dns_state_key                               = null
dns_state_role                              = null
shared_state_bucket                         = "di-auth-development-tfstate"
test_clients_enabled                        = "true"
ipv_api_enabled                             = true
ipv_authorisation_callback_uri              = ""
ipv_authorisation_uri                       = ""
ipv_authorisation_client_id                 = ""
logging_endpoint_enabled                    = false
logging_endpoint_arns                       = []
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true
account_intervention_service_abort_on_error = true
send_storage_token_to_ipv_enabled           = true

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

lambda_max_concurrency = 0
lambda_min_concurrency = 0
endpoint_memory_size   = 1536


lockout_duration                          = 30
otp_code_ttl_duration                     = 120
email_acct_creation_otp_code_ttl_duration = 60


orch_client_id  = "orchestrationAuth"
orch_account_id = "816047645251"

contra_state_bucket = "di-auth-development-tfstate"

orch_frontend_api_gateway_integration_enabled = false

orch_redirect_uri = "https://oidc.authdev1.sandpit.account.gov.uk/orchestration-redirect"

authorize_protected_subnet_enabled = true

oidc_origin_domain_enabled = true
