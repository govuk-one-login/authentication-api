doc_app_api_enabled                = true
doc_app_cri_data_endpoint          = "credentials/issue"
doc_app_backend_uri                = "https://build-doc-app-cri-stub.london.cloudapps.digital"
doc_app_domain                     = "https://build-doc-app-cri-stub.london.cloudapps.digital"
doc_app_authorisation_client_id    = "authOrchestrator"
doc_app_authorisation_callback_uri = "https://oidc.build.account.gov.uk/doc-checking-app-callback"
doc_app_authorisation_uri          = "https://build-doc-app-cri-stub.london.cloudapps.digital/authorize"
doc_app_auth_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvnQV8yrKnVObCMg+ZNLQ
P37gEe+fGAvaM/kAq05M10GREqk7zcIHD4i3xtKTmeJwLg/TPbPvNCQ5jWv9Zt54
HnSe0f6xSkkbAiNiqqcsYhP6v8o6p0VvvoiGZDDOw5mVsBDqi/NwOs8a476MN0Wa
hYUb9c/Wi+dYgtl89oPEYTmghIrDPm+66gAlTtn7PLST09sRQ8HgIoFGlElaJV0E
mex/gmWg215zlR4wMD+feYi8K9Impskbxa8M2Pyrwh839asByf9ybrp/IiYBWDdj
ISiWaUZiNN465RphH8VZOa0r06y04tNIoDKar1dNcU/SEkNjpV6WUJJgUmChdUyS
LwIDAQAB
-----END PUBLIC KEY-----
EOT
doc_app_cri_public_signing_key     = <<-EOT
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUJAIhznCaDeZDtQEj4SVNSSGF5Pj
vqyuq8GafzksD3ZzdciYKgl1X4fMxWmpNLU8TaTtAlVHTM+8mtUGPmCCtA==
-----END PUBLIC KEY-----
EOT

blocked_email_duration = 30

logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prod",
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]