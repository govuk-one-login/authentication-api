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

auth_frontend_public_encryption_key = <<-EOT
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

enable_api_gateway_execution_request_tracing = false
spot_enabled                                 = false

lambda_max_concurrency = 0
lambda_min_concurrency = 0
endpoint_memory_size   = 1536


lockout_duration                          = 30
otp_code_ttl_duration                     = 120
email_acct_creation_otp_code_ttl_duration = 60

extended_feature_flags_enabled = false

orch_client_id = "orchestrationAuth"

support_auth_orch_split = true

support_auth_orch_split_user_info = true

orch_frontend_api_gateway_integration_enabled = false

orch_redirect_uri = "https://oidc.authdev1.sandpit.account.gov.uk/orchestration-redirect"

authorize_protected_subnet_enabled = true

support_email_check_enabled = true