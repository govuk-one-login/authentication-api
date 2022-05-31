notify_template_map = {
  VERIFY_EMAIL_TEMPLATE_ID                 = "ea5a548b-a071-4d24-9a9a-1138673f25ce"
  VERIFY_PHONE_NUMBER_TEMPLATE_ID          = "16608047-106e-4fe9-bf3a-b1676e29eca9"
  MFA_SMS_TEMPLATE_ID                      = "16608047-106e-4fe9-bf3a-b1676e29eca9"
  RESET_PASSWORD_TEMPLATE_ID               = "cc30aac4-4aae-4706-b147-9df40bd2feb8"
  PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID  = "99a548c9-b974-4933-9451-c85b3d6b6172"
  ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID = "360b4786-0b34-45e2-b909-88de67490a0e"
  RESET_PASSWORD_WITH_CODE_TEMPLATE_ID     = "59114c22-a2f1-40c8-a530-f337112415ef"
}

cloudwatch_log_retention    = 5
lambda_min_concurrency      = 50
client_registry_api_enabled = false
ipv_api_enabled             = false
ipv_capacity_allowed        = false
spot_enabled                = true

ipv_authorisation_client_id    = "authOrchestrator"
ipv_auth_public_encryption_key = <<-EOT
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
