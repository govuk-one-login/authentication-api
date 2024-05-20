environment                                 = "authdev2"
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

lambda_max_concurrency = 0
lambda_min_concurrency = 0
endpoint_memory_size   = 1536

lockout_duration                          = 30
otp_code_ttl_duration                     = 120
email_acct_creation_otp_code_ttl_duration = 60


orch_client_id = "orchestrationAuth"

contra_state_bucket      = "di-auth-development-tfstate"
phone_checker_with_retry = false

orch_redirect_uri                  = "https://oidc.authdev2.sandpit.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled = true

support_email_check_enabled = true


oidc_origin_domain_enabled = true
