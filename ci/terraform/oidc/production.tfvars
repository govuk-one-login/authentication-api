oidc_api_lambda_zip_file             = "./artifacts/oidc-api.zip"
frontend_api_lambda_zip_file         = "./artifacts/frontend-api.zip"
client_registry_api_lambda_zip_file  = "./artifacts/client-registry-api.zip"
ipv_api_lambda_zip_file              = "./artifacts/ipv-api.zip"
doc_checking_app_api_lambda_zip_file = "./artifacts/doc-checking-app-api.zip"
logging_endpoint_arn                 = ""
logging_endpoint_arns                = []
shared_state_bucket                  = "digital-identity-prod-tfstate"
test_clients_enabled                 = false
internal_sector_uri                  = "https://identity.account.gov.uk"

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

orch_client_id    = "orchestrationAuth"
orch_redirect_uri = "https://oidc.account.gov.uk/orchestration-redirect"
