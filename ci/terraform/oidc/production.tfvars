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

ipv_backend_uri            = "https://api.identity.account.gov.uk"
evcs_audience              = "https://credential-store.account.gov.uk"
auth_issuer_claim_for_evcs = "https://signin.account.gov.uk"

# The IPV public encrypting key that is specific to auth.
# This was calculated from the production IPV wel known endpoint:
# https://api.identity.account.gov.uk/.well-known/jwks.json
auth_frontend_api_to_ipv_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4K/6GH//FQSD6Yk/5nKY
zRCwrYcQy7wGHH2cZ7EXo/9+SNRcbQlzd+NVTplIk9x7+t7g8U36z/I8CM/woGgJ
zM8DNREecxH/4YEYKOqbqHSnK7iICJ18Wfb+mNr20Dt+Ik1oQja6aKPqIj4Jl4WW
0vHMhDfUNP/iOi3zhNJsTZwYjVQWqLzmWfAqO/61d2XbLDIgubKqAtTFWnxeXuBU
VZAbq03qmvzyekRUvZtck7JuQUa9mj2gJC0YPLoLDM+j0QDGWrPnDA2L2VmmF1wn
rbeA0zSUxxfdffFH/L0cTgzdTQtv6iGQrkfHnTTk1TQe0+wxJEQz5FlcXYl6qSrh
swIDAQAB
-----END PUBLIC KEY-----
EOT

# AUTH to IPV reverification
# auth only
ipv_auth_authorize_callback_uri = "https://signin.account.gov.uk/ipv/callback/authorize"
ipv_auth_authorize_client_id    = "auth"


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

lockout_duration                     = 7200
incorrect_password_lockout_count_ttl = 7200

orch_client_id                     = "orchestrationAuth"
orch_redirect_uri                  = "https://oidc.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled = true

contra_state_bucket = "digital-identity-prod-tfstate"

orch_account_id                       = "533266965190"
is_orch_stubbed                       = false
orch_environment                      = "production"
orch_session_table_encryption_key_arn = "arn:aws:kms:eu-west-2:533266965190:key/7ad27a55-9d21-47f2-be03-b61f2c9a8ce6"

orch_trustmark_enabled               = true
orch_openid_configuration_enabled    = true
orch_jwks_enabled                    = true
orch_authorisation_enabled           = true
orch_auth_code_enabled               = true
orch_token_enabled                   = true
orch_userinfo_enabled                = true
orch_ipv_callback_enabled            = true
orch_doc_app_callback_enabled        = true
orch_authentication_callback_enabled = true
orch_logout_enabled                  = true
auth_spot_response_disabled          = true
orch_storage_token_jwk_enabled       = true
