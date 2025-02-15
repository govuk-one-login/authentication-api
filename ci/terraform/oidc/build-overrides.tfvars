doc_app_cri_data_endpoint                   = "credentials/issue"
doc_app_backend_uri                         = "https://dcmaw-cri.build.stubs.account.gov.uk"
doc_app_domain                              = "https://dcmaw-cri.build.stubs.account.gov.uk"
doc_app_authorisation_client_id             = "orch-build"
doc_app_authorisation_callback_uri          = "https://oidc.build.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri                   = "https://dcmaw-cri.build.stubs.account.gov.uk/authorize"
doc_app_jwks_endpoint                       = "https://dcmaw-cri.build.stubs.account.gov.uk/.well-known/jwks.json"
doc_app_aud                                 = "https://dcmaw-cri.build.stubs.account.gov.uk"
doc_app_new_aud_claim_enabled               = true
doc_app_encryption_key_id                   = "dcmaw-cri-stubs-build-INqHBvMYWmNodklvbpTCgf1DS10Fv5ic4_8LdoBNjAw"
spot_enabled                                = false
internal_sector_uri                         = "https://identity.build.account.gov.uk"
custom_doc_app_claim_enabled                = true
ipv_audience                                = "https://ipvstub.signin.build.account.gov.uk"
evcs_audience                               = "https://credential-store.build.account.gov.uk"
auth_issuer_claim_for_evcs                  = "https://signin-sp.build.account.gov.uk"
doc_app_cri_data_v2_endpoint                = "credentials/issue"
orch_client_id                              = "orchestrationAuth"
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true
# account_intervention_service_uri is stored in AWS Secrets Manager and populated using read_secrets.sh
support_reauth_signout_enabled          = true
authentication_attempts_service_enabled = true
send_storage_token_to_ipv_enabled       = true
auth_frontend_public_encryption_key     = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApLJWOHz7uHLinSJr8XM0
fhyq0aLm8HP06lCT7csGUoRav2xybsCsypufvJHbuD5SLkg25/VGFt21KH2g60u8
6mV7ULLG/m4hvAiXbwSGdcRTToPS+UULX3YDnDXZHvd+3ypane82+XLjVZ9B2V0i
1MGCJ7kiRurXCuE+9Kx/MQYBCqhz/OwHlCe3FJZXKvgnqqpO5ZtyjrxDJSZJpxbi
KsVnLksPKV10Z0/XvpJ6oHtOjseetk8TRdekRWBvqCX5MqLjdi1TfiaDu2Tjg2N0
dqhoDR3/THktb4KThc+U5EOWCWpH4OIAetYtjFChnkR8kU05Ol9zfdR08uO0RxMk
1wIDAQAB
-----END PUBLIC KEY-----
EOT

# The IPV public encrypting key that is specific to auth.
auth_frontend_api_to_ipv_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmZX3zqqtMpPidaeaSxQj
nn5/Uc53VzZCYoaCejQfjDJf3ez9D0x7rpTuZepG566xr50nkKdW7s/UWGKAc8+w
wagazGi5dmaUjks2Kx5AUAnwy803KNqEEguS49GDaliSUIwPIOvekGvBGpwt/IW6
k56B/SU1eeMXaaSTgmTiILHkvN4znYMvihlg2TXOdfBXJvgCL/p4D4DXvJ3AoL33
SZ9gmgcJTGYQDYYXUFSI5/iNAGUrFIy3A6l0gFt33C7Yqrm69qPnpB1jbaEC8ZXp
Jjkeija5UzWqUQVTzLPTonx2VZ6C/duCTSD8OqdrM4TAAa2zBDP9b1KH2hh2nlmw
2QIDAQAB
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
