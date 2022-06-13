notify_template_map = {
  VERIFY_EMAIL_TEMPLATE_ID         = "ea5a548b-a071-4d24-9a9a-1138673f25ce"
  VERIFY_PHONE_NUMBER_TEMPLATE_ID  = "16608047-106e-4fe9-bf3a-b1676e29eca9"
  EMAIL_UPDATED_TEMPLATE_ID        = "4dcce0b8-54cd-41c7-8dfc-e4b994a5f2ce"
  DELETE_ACCOUNT_TEMPLATE_ID       = "2c57d906-0238-410f-a3a5-cedb09b6c14d"
  PHONE_NUMBER_UPDATED_TEMPLATE_ID = "beaf3eb2-135c-4517-800b-ca6b5ed85804"
  PASSWORD_UPDATED_TEMPLATE_ID     = "8d4c4948-000a-4de0-a8ba-76c259c1f983"
}

cloudwatch_log_retention = 5

performance_tuning = {
  authorizer = {
    memory          = 1024
    concurrency     = 3
    max_concurrency = 10
    scaling_trigger = 0.6
  }
}

lambda_max_concurrency = 10
lambda_min_concurrency = 3
keep_lambdas_warm      = false
endpoint_memory_size   = 1024
scaling_trigger        = 0.6
