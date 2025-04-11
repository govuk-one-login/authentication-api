oidc_api_lambda_zip_file             = "./artifacts/oidc-api.zip"
frontend_api_lambda_zip_file         = "./artifacts/frontend-api.zip"
client_registry_api_lambda_zip_file  = "./artifacts/client-registry-api.zip"
ipv_api_lambda_zip_file              = "./artifacts/ipv-api.zip"
doc_checking_app_api_lambda_zip_file = "./artifacts/doc-checking-app-api.zip"
shared_state_bucket                  = "digital-identity-dev-tfstate"

# FMS
frontend_api_fms_tag_value = "authfrontendint"

# App-specific
internal_sector_uri                     = "https://identity.integration.account.gov.uk"
test_clients_enabled                    = false
call_ticf_cri                           = true
support_reauth_signout_enabled          = true
authentication_attempts_service_enabled = true

## AUTH to IPV reverification
## auth only
ipv_auth_authorize_callback_uri = "https://signin.integration.account.gov.uk/ipv/callback/authorize"
ipv_auth_authorize_client_id    = "auth"


auth_to_orch_token_signing_public_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvvr/3/mHEPLpgsLR3ocLiGrVpVLJ
AZUx4RCDu+VWAZpPi1NaF5XWvkFNFwH+MyLkATh90UEJDe+ayKW6AXFcRQ==
-----END PUBLIC KEY-----
EOT

lockout_duration                     = 7200
incorrect_password_lockout_count_ttl = 7200

orch_redirect_uri                  = "https://oidc.integration.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled = true

contra_state_bucket = "digital-identity-dev-tfstate"

orch_account_id                                    = "058264132019"
is_orch_stubbed                                    = false
orch_environment                                   = "integration"
orch_session_table_encryption_key_arn              = "arn:aws:kms:eu-west-2:058264132019:key/1b5c001b-ed53-4a7b-bfbe-5d0f596110b5"
orch_client_session_table_encryption_key_arn       = "arn:aws:kms:eu-west-2:058264132019:key/fdf1686f-2d4d-4c7b-b3be-324b6ebba370"
orch_identity_credentials_table_encryption_key_arn = "arn:aws:kms:eu-west-2:058264132019:key/808a8c1e-82d8-487e-abb8-e13d6564b426"

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
orch_register_enabled                = true
orch_storage_token_jwk_enabled       = true
orch_ipv_jwks_enabled                = true
doc_app_cri_data_endpoint            = "userinfo"
doc_app_backend_uri                  = "https://api-backend-api.review-b.integration.account.gov.uk"
doc_app_domain                       = "https://api.review-b.integration.account.gov.uk"
doc_app_aud                          = "https://www.review-b.integration.account.gov.uk"
doc_app_new_aud_claim_enabled        = true
doc_app_authorisation_client_id      = "authOrchestratorDocApp"
doc_app_authorisation_callback_uri   = "https://oidc.integration.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri            = "https://www.review-b.integration.account.gov.uk/dca/oauth2/authorize"
doc_app_jwks_endpoint                = "https://api-backend-api.review-b.integration.account.gov.uk/.well-known/jwks.json"
doc_app_encryption_key_id            = "0948190d-384c-498d-81e2-a20dd30f147c"
doc_app_cri_data_v2_endpoint         = "userinfo/v2"

ipv_api_enabled                             = true
ipv_capacity_allowed                        = true
ipv_authorisation_client_id                 = "authOrchestrator"
ipv_authorisation_uri                       = "https://identity.integration.account.gov.uk/oauth2/authorize"
ipv_authorisation_callback_uri              = "https://oidc.integration.account.gov.uk/ipv-callback"
ipv_backend_uri                             = "https://api.identity.integration.account.gov.uk"
ipv_audience                                = "https://identity.integration.account.gov.uk"
evcs_audience                               = "https://credential-store.integration.account.gov.uk"
auth_issuer_claim_for_evcs                  = "https://signin.integration.account.gov.uk"
spot_enabled                                = true
custom_doc_app_claim_enabled                = true
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true

auth_frontend_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAojSigrHTBqF/2xuSptZo
rifAahfOOD6BKOfRMZauLYLITU7+AASC+oIUU8vfJ6yMstuLbrpFHQ5lPgnbNQ4h
Hp91wzXl2w/4TPgx9sH6AIVEe0nzM7w808jzGK1xkqeDN24TSdTCS9uU340K+1lg
vHJ6RPURwpGKmwi/yQs4aEdBswK1qjdwtyz3KQF6a5sI3d4uCwtsLYfwD+yxIVnX
L5tIdMLWFTMX7PCN24cwWFMz8JJr5D/3Gujy3oEJgaBLVSkBEQcGcR9zTcF46e0x
qZM9NOP2fgb26CFV/vGQj21Jo+z4NK9+3doXwVESaw+8iTvlavUg1l91cJ1iHzde
UQIDAQAB
-----END PUBLIC KEY-----
EOT

ipv_auth_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzgTML6YZ+XUEPQprWBlW
oZ9FwasmRGsdLHLgAhyNWDw4PtYaihhpSOxoI+86IeO1qAe1nfqrFGW+X37jxDBz
clY/TxQkivEQqLCWmohuFcpn5dxz6SSC+WFhwLtedC8gXUv1JP4E0mgr7OKWh7t3
RQcpGyTaAGXh2wywZXytVOLDcwwPb0PeFiC8MR0A8tIpYyx1yXjKcs1Aga8Xy0HF
V9pU5gbB7a/XLl7j3CHePsfImYi4wG17y+jbN7+vF3GDpAqyRa78ctTZT9/WBWzP
cX8yiRmHf7ID9br2MsdrTO9YyVWfI0z7OZB1GnNe5lJhGBXvd3xg4UjWbnHikliE
NQIDAQAB
-----END PUBLIC KEY-----
EOT

## The IPV public encrypting key that is specific to auth.
## Note: ipv_auth_public_encryption_key, above, is owned and used by orchestration.
auth_frontend_api_to_ipv_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzgTML6YZ+XUEPQprWBlW
oZ9FwasmRGsdLHLgAhyNWDw4PtYaihhpSOxoI+86IeO1qAe1nfqrFGW+X37jxDBz
clY/TxQkivEQqLCWmohuFcpn5dxz6SSC+WFhwLtedC8gXUv1JP4E0mgr7OKWh7t3
RQcpGyTaAGXh2wywZXytVOLDcwwPb0PeFiC8MR0A8tIpYyx1yXjKcs1Aga8Xy0HF
V9pU5gbB7a/XLl7j3CHePsfImYi4wG17y+jbN7+vF3GDpAqyRa78ctTZT9/WBWzP
cX8yiRmHf7ID9br2MsdrTO9YyVWfI0z7OZB1GnNe5lJhGBXvd3xg4UjWbnHikliE
NQIDAQAB
-----END PUBLIC KEY-----
EOT


# Logging
logging_endpoint_arns = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]

# Sizing
performance_tuning = {
  register = {
    memory          = 512
    concurrency     = 0
    max_concurrency = 0
    scaling_trigger = 0
  }

  update = {
    memory          = 512
    concurrency     = 0
    max_concurrency = 0
    scaling_trigger = 0
  }
}
lambda_min_concurrency = 1
