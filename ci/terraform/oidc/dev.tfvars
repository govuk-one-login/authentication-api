oidc_api_lambda_zip_file                = "./artifacts/oidc-api.zip"
frontend_api_lambda_zip_file            = "./artifacts/frontend-api.zip"
client_registry_api_lambda_zip_file     = "./artifacts/client-registry-api.zip"
ipv_api_lambda_zip_file                 = "./artifacts/ipv-api.zip"
doc_checking_app_api_lambda_zip_file    = "./artifacts/doc-checking-app-api.zip"
logging_endpoint_arn                    = ""
logging_endpoint_arns                   = []
shared_state_bucket                     = "di-auth-development-tfstate"
test_clients_enabled                    = true
internal_sector_uri                     = "https://identity.dev.account.gov.uk"
call_ticf_cri                           = true
ipv_authorisation_callback_uri          = "https://signin.dev.account.gov.uk/ipv/callback/authorize"
ipv_authorisation_client_id             = "authTestClient"
ipv_authorisation_uri                   = "https://ipvstub.signin.dev.account.gov.uk/authorize/"
ipv_backend_uri                         = "https://ipvstub.signin.dev.account.gov.uk"
authentication_attempts_service_enabled = true

# lockout config
lockout_duration                     = 60
reduced_lockout_duration             = 30
incorrect_password_lockout_count_ttl = 60
lockout_count_ttl                    = 60
otp_code_ttl_duration                = 60

auth_frontend_public_encryption_key = <<-EOT
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

auth_to_orch_token_signing_public_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESgoCw5pZYyGtFpPBV2YfU3DGrDqC
8UKoRGN4gYTbuwAsLkOSYYY8BM7dhSEhgF4DX9i66HXjteogg6mhOZI1mA==
-----END PUBLIC KEY-----
EOT

ipv_authorization_public_key = <<-EOT
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

orch_client_id                     = "orchestrationAuth"
orch_redirect_uri                  = "https://oidc.dev.account.gov.uk/orchestration-redirect"
authorize_protected_subnet_enabled = true

orch_account_id = "816047645251"
is_orch_stubbed = true

contra_state_bucket = "di-auth-development-tfstate"

oidc_cloudfront_enabled = false
