doc_app_cri_data_endpoint          = "userinfo"
doc_app_backend_uri                = "https://api-backend-api.review-b.integration.account.gov.uk"
doc_app_domain                     = "https://api.review-b.integration.account.gov.uk"
doc_app_aud                        = "https://www.review-b.integration.account.gov.uk"
doc_app_new_aud_claim_enabled      = true
doc_app_authorisation_client_id    = "authOrchestratorDocApp"
doc_app_authorisation_callback_uri = "https://oidc.integration.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri          = "https://www.review-b.integration.account.gov.uk/dca/oauth2/authorize"
doc_app_jwks_endpoint              = "https://api-backend-api.review-b.integration.account.gov.uk/.well-known/jwks.json"
doc_app_encryption_key_id          = "0948190d-384c-498d-81e2-a20dd30f147c"
doc_app_cri_data_v2_endpoint       = "userinfo/v2"

ipv_api_enabled                             = true
ipv_capacity_allowed                        = true
ipv_authorisation_client_id                 = "authOrchestrator"
ipv_authorisation_uri                       = "https://identity.integration.account.gov.uk/oauth2/authorize"
ipv_authorisation_callback_uri              = "https://oidc.integration.account.gov.uk/ipv-callback"
ipv_backend_uri                             = "https://api.identity.integration.account.gov.uk"
ipv_audience                                = "https://identity.integration.account.gov.uk"
internal_sector_uri                         = "https://identity.integration.account.gov.uk"
spot_enabled                                = true
custom_doc_app_claim_enabled                = true
orch_client_id                              = "orchestrationAuth"
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

logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]

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
lambda_max_concurrency = 0
lambda_min_concurrency = 1
endpoint_memory_size   = 1536
scaling_trigger        = 0.6
