common_state_bucket = "digital-identity-prod-tfstate"

# Notify
notify_template_map = {
  VERIFY_EMAIL_TEMPLATE_ID                               = "09f29c9a-3f34-4a56-88f5-8197aede7f85,bda5cfb3-3d91-407e-90cc-b690c1fa8bf9"
  PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID                = "c5a6a8d6-0a45-4496-bec8-37167fc6ecaa,4afbd99d-7745-4c9e-9caf-a1c054b74998"
  ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID               = "99580afe-9d3f-4ed1-816d-3b583a7b9167,08e0027d-a087-41f1-a5ae-7c862732ed99"
  RESET_PASSWORD_WITH_CODE_TEMPLATE_ID                   = "4f76b165-8935-49fe-8ba8-8ca62a1fe723,ed08fced-e960-4261-8b28-12cb2907cbdf"
  EMAIL_UPDATED_TEMPLATE_ID                              = "22aac1ce-38c7-45f5-97b2-26ac1a54a235,17540bf2-5d77-4ac2-be34-ba89c728c60b"
  DELETE_ACCOUNT_TEMPLATE_ID                             = "1540bdda-fdff-4297-b627-92102e061bfa,9a212a1d-5bfc-4e7f-80fa-033d3ae03a1c"
  PHONE_NUMBER_UPDATED_TEMPLATE_ID                       = "8907d080-e69c-42c6-8cf5-54ca1558a2e4,d12aaa12-1590-4d3d-b75e-e513d299b1b6"
  PASSWORD_UPDATED_TEMPLATE_ID                           = "ebf3730c-0769-462b-ab39-7d9a7439bac1,435cf040-2dfc-4d1c-838d-2f349c8d11f1"
  VERIFY_PHONE_NUMBER_TEMPLATE_ID                        = "8babad52-0e2e-443a-8a5a-c296dc1696cc,4bbc0a5c-833a-490e-89c6-5e286a030ac6"
  MFA_SMS_TEMPLATE_ID                                    = "31e48dbf-6db6-4864-9710-081b72746698,044a2369-420c-4518-85ca-3fe1b9a93244"
  AM_VERIFY_EMAIL_TEMPLATE_ID                            = "98fdb807-d0d8-41c8-a1d7-7d0abff06b3c"
  AM_VERIFY_PHONE_NUMBER_TEMPLATE_ID                     = "b1b3935d-ffdc-4853-a3cd-a9fce09dbff5"
  PASSWORD_RESET_CONFIRMATION_SMS_TEMPLATE_ID            = "86a27ea9-e8ac-423f-a444-b2751e165887"
  VERIFY_CHANGE_HOW_GET_SECURITY_CODES_TEMPLATE_ID       = "49b3aea6-9a67-4ef4-af08-3297c1cce82c"
  CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION_TEMPLATE_ID = "d253a170-8144-4471-b339-c35965c9298a"
  TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID            = "173418a1-c442-4c4b-a6d1-d23f473f3dd0"
  REPORT_SUSPICIOUS_ACTIVITY_EMAIL_TEMPLATE_ID           = "0674c6e3-219c-4e3a-b04c-3786bac7f228"
  BACKUP_METHOD_ADDED_TEMPLATE_ID                        = "569ae40c-2631-4de3-9d85-7f8ffd9182e9"
  BACKUP_METHOD_REMOVED_TEMPLATE_ID                      = "8c8d2392-cecc-452d-88a5-2bd8418fb257"
  CHANGED_AUTHENTICATOR_APP_TEMPLATE_ID                  = "de419864-17bf-488c-93e5-da791352e2db"
  CHANGED_DEFAULT_MFA_TEMPLATE_ID                        = "2d17c6db-8d2d-42af-95f1-5d096cd74212"
  SWITCHED_MFA_METHODS_TEMPLATE_ID                       = "0b856ef8-07d6-4dca-ab6a-8a45044182cc"
}

# Logging
logging_endpoint_arns    = ["arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"]
cloudwatch_log_retention = 30

# Sizing
lambda_min_concurrency = 25

# FMS
frontend_api_fms_tag_value = "authfrontendprod"
