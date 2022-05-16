ipv_api_enabled                = false
ipv_capacity_allowed           = false
ipv_authorisation_client_id    = "authOrchestrator"
ipv_authorisation_uri          = "https://integration-di-ipv-core-front.london.cloudapps.digital/oauth2/authorize"
ipv_authorisation_callback_uri = "https://oidc.integration.account.gov.uk/ipv-callback"
ipv_backend_uri                = "https://18zwbqzm0k.execute-api.eu-west-2.amazonaws.com/integration"
ipv_sector                     = "https://identity.integration.account.gov.uk"
ipv_auth_public_encryption_key = <<-EOT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAup9XBBawAJ99ZfahfOEu
RlJtourP+dytAdLOCsvRiMREvpuhBLJJgeEXZ3GwvH8qgysj9y1fp6KU/xVNxnSw
vj44JPyjwG7Sen7z46GjKZ2TGK21Ia7Td7kE+NA9Bs7WU2Se+MvuOvF5WqS5qSTO
peOd/QYLrb61scdEH0qn0FkMD85aOTEcrbKu+aG7wtpcds6p7+YyL8xtod7eQS6l
VrhX2LFvYht4l1tT1ldOg1ggyYhgXxjDjp4QHWJDUsnmEyDAg1ST0sHt+lWEh3N8
nEgJUHjGrjO5TYDiL7+Qhl58SsO8gJQVgyWOFLwMQAHtcfC1pM89VzabA2aNNoXF
hwIDAQAB
-----END PUBLIC KEY-----
EOT
logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prod",
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]