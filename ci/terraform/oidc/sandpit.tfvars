environment                                 = "sandpit"
dns_state_bucket                            = null
dns_state_key                               = null
dns_state_role                              = null
shared_state_bucket                         = "digital-identity-dev-tfstate"
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
call_ticf_cri                               = true
auth_frontend_public_encryption_key         = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs41htFRe62BIfwQZ0OCT
g5p2NHAekvIAJaNb6ZkLuLXYdLBax+2c9f4ALTrltmLMBpgtS6VQg2zO8UmSE4bX
+Nhaw2nf3/VRBIlAi2NiD4cUIwNtxIx5qpBeDxb+YR7NuTJ0nFq6u6jv34RB1RWE
J1sEOiv9aSPEt6eK8TGL6uZbPGU8CKJuWwPfW1ko/lyuM1HG0G/KAZ8DaLJzOMWX
+2aZatj9RHtOCtGxwMrZlU4n/O1gbVPBfXx9RugTi0W4upmeNFR5CsC+WgENkr0v
pXEyIW7edR6lDsSYzJI+yurVFyt82Bn7Vo2x5CIoLiH/1ZcKaApNU02/eK/gMBf+
EwIDAQAB
-----END PUBLIC KEY-----
EOT

auth_to_orch_token_signing_public_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvvr/3/mHEPLpgsLR3ocLiGrVpVLJ
AZUx4RCDu+VWAZpPi1NaF5XWvkFNFwH+MyLkATh90UEJDe+ayKW6AXFcRQ==
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

orch_client_id = "orchestrationAuth"

orch_frontend_api_gateway_integration_enabled = true

orch_redirect_uri                  = "https://oidc.sandpit.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled = true

support_email_check_enabled = true

contra_state_bucket = "digital-identity-dev-tfstate"

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

orch_account_id                     = "816047645251"
cmk_for_back_channel_logout_enabled = true

oidc_origin_domain_enabled  = true
oidc_cloudfront_dns_enabled = true
enforce_cloudfront          = true
