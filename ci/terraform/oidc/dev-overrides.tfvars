doc_app_cri_data_endpoint                   = "credentials/issue"
doc_app_backend_uri                         = "https://dcmaw-cri.dev.stubs.account.gov.uk"
doc_app_domain                              = "https://dcmaw-cri.dev.stubs.account.gov.uk"
doc_app_authorisation_client_id             = "orch-dev"
doc_app_authorisation_callback_uri          = "https://oidc.dev.account.gov.uk/doc-app-callback"
doc_app_authorisation_uri                   = "https://dcmaw-cri.dev.stubs.account.gov.uk/authorize"
doc_app_jwks_endpoint                       = "https://dcmaw-cri.dev.stubs.account.gov.uk/.well-known/jwks.json"
doc_app_aud                                 = "https://dcmaw-cri.dev.stubs.account.gov.uk"
doc_app_new_aud_claim_enabled               = true
doc_app_encryption_key_id                   = ""
spot_enabled                                = false
internal_sector_uri                         = "https://identity.dev.account.gov.uk"
custom_doc_app_claim_enabled                = true
ipv_audience                                = "https://ipvstub.signin.dev.account.gov.uk"
doc_app_cri_data_v2_endpoint                = "credentials/issue"
orch_client_id                              = "orchestrationAuth"
account_intervention_service_call_enabled   = true
account_intervention_service_action_enabled = true
# account_intervention_service_uri is stored in AWS Secrets Manager and populated using read_secrets.sh
account_intervention_service_abort_on_error = true
send_storage_token_to_ipv_enabled           = true
auth_frontend_public_encryption_key         = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0PcOHuVXOuexYZmpOlCo
vFcGfezObHnnVTTfnCrS5TBmAEC9JNwH/YFmE/zx84I1dy5fEjll+2GIe8Hcue+W
ubQMToFaAAeaqowqjgJYIPjgTubJ+baAP7+6GFPBWkk+LntBRQaoF7YkICT6im9h
JTrFb5KxyDNT/j4SCCXlkMTzqmeMVM59NM66MSS7OXsUny9GinG6xhDovUswvU99
N7GtGZBYIDmG6IrT/rS9ZosBLeLqCvRAfaYjq0/2EKHcudyeYjPDkkGpBNt7vXJJ
A+Ud3Nx8MmuKS3kb8NoDhQJxKxg7lgjAj+Lhb9xr+Y074hdTs5ju2Jx2tmP1y9vl
RwIDAQAB
-----END PUBLIC KEY-----
EOT

#
# Shared with Orchestration
#
ipv_audience = "https://ipvstub.signin.dev.account.gov.uk"

#
# Auth specific overrides
#
auth_issuer_claim_for_ipv       = "auth"
auth_issuer_claim               = "https://signin.dev.account.gov.uk"
evcs_audience                   = "https://credential-store.dev.account.gov.uk"
ipv_auth_authorize_callback_uri = "https://signin.dev.account.gov.uk/ipv/callback/authorize"
ipv_auth_authorize_client_id    = "authTestClient"

# The IPV public encrypting key that is specific to auth.
auth_frontend_api_to_ipv_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArukFibN4qI+/0SbSrMLg
8v7Lj3KdV7tktgd+dol8VwDxMVfci0+5debd6yJFM6wgenCRI2FIxRXi+59bVgGY
TwNENEaoaYfvb7CL6I7bYv0O5JOW6nJmA0md+7jb3zEpJk7bf8Syt2IilEZCUxv2
MVDsk+GLTt2RHGi9pOgGAWeKb9OugsmYHEIlZ7OjKnjHnLhYDrALRFOdXN5PimSM
Fd/HiEzFuxltuiQ7GXCmV/y1fND3SipvJOpnOJfJQuA696MrzIWgVt7GBfGbRSWF
/45dQPPyNlvjm+VHUavcU3aB6/rtKWpLBg2oOaGnjHsgxjo62bGS6mkDBluku2NO
gQIDAQAB
-----END PUBLIC KEY-----
EOT

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
