cloudwatch_log_retention = 5
lambda_min_concurrency   = 25

notify_template_map = {
  VERIFY_EMAIL_TEMPLATE_ID                 = "ea5a548b-a071-4d24-9a9a-1138673f25ce,bda5cfb3-3d91-407e-90cc-b690c1fa8bf9"
  RESET_PASSWORD_TEMPLATE_ID               = "cc30aac4-4aae-4706-b147-9df40bd2feb8"
  PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID  = "99a548c9-b974-4933-9451-c85b3d6b6172,4afbd99d-7745-4c9e-9caf-a1c054b74998"
  ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID = "360b4786-0b34-45e2-b909-88de67490a0e,08e0027d-a087-41f1-a5ae-7c862732ed99"
  RESET_PASSWORD_WITH_CODE_TEMPLATE_ID     = "59114c22-a2f1-40c8-a530-f337112415ef,ed08fced-e960-4261-8b28-12cb2907cbdf"
  EMAIL_UPDATED_TEMPLATE_ID                = "4dcce0b8-54cd-41c7-8dfc-e4b994a5f2ce,17540bf2-5d77-4ac2-be34-ba89c728c60b"
  DELETE_ACCOUNT_TEMPLATE_ID               = "2c57d906-0238-410f-a3a5-cedb09b6c14d,9a212a1d-5bfc-4e7f-80fa-033d3ae03a1c"
  PHONE_NUMBER_UPDATED_TEMPLATE_ID         = "beaf3eb2-135c-4517-800b-ca6b5ed85804,d12aaa12-1590-4d3d-b75e-e513d299b1b6"
  PASSWORD_UPDATED_TEMPLATE_ID             = "8d4c4948-000a-4de0-a8ba-76c259c1f983,435cf040-2dfc-4d1c-838d-2f349c8d11f1"
  VERIFY_PHONE_NUMBER_TEMPLATE_ID          = "16608047-106e-4fe9-bf3a-b1676e29eca9,4bbc0a5c-833a-490e-89c6-5e286a030ac6"
  MFA_SMS_TEMPLATE_ID                      = "6b9b6c82-a8c0-4b39-990b-a10130467f1e,044a2369-420c-4518-85ca-3fe1b9a93244"
}

logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]
