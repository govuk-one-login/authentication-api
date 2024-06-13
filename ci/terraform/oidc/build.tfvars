oidc_api_lambda_zip_file             = "./artifacts/oidc-api.zip"
frontend_api_lambda_zip_file         = "./artifacts/frontend-api.zip"
client_registry_api_lambda_zip_file  = "./artifacts/client-registry-api.zip"
ipv_api_lambda_zip_file              = "./artifacts/ipv-api.zip"
doc_checking_app_api_lambda_zip_file = "./artifacts/doc-checking-app-api.zip"
logging_endpoint_arn                 = ""
logging_endpoint_arns                = []
shared_state_bucket                  = "digital-identity-dev-tfstate"
test_clients_enabled                 = true
internal_sector_uri                  = "https://identity.build.account.gov.uk"
ipv_api_enabled                      = true

# lockout config
lockout_duration                     = 60
reduced_lockout_duration             = 30
incorrect_password_lockout_count_ttl = 60
lockout_count_ttl                    = 60
otp_code_ttl_duration                = 60

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

orch_client_id                     = "orchestrationAuth"
orch_redirect_uri                  = "https://oidc.build.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled = true

contra_state_bucket = "digital-identity-dev-tfstate"

orch_account_id = "767397776536"

oidc_origin_domain_enabled  = true
oidc_cloudfront_dns_enabled = true
enforce_cloudfront          = true
txma_audit_encoded_enabled  = true

kms_cross_account_access_enabled                = true
spot_request_queue_cross_account_access_enabled = true
orch_storage_token_jwk_enabled                  = true
orch_trustmark_enabled                          = true
orch_openid_configuration_enabled               = true
orch_jwks_enabled                               = true
orch_register_enabled                           = true
orch_authorisation_enabled                      = true
