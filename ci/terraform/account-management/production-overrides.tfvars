notify_template_map = {
  VERIFY_EMAIL_TEMPLATE_ID         = "bda5cfb3-3d91-407e-90cc-b690c1fa8bf9"
  VERIFY_PHONE_NUMBER_TEMPLATE_ID  = "4bbc0a5c-833a-490e-89c6-5e286a030ac6"
  EMAIL_UPDATED_TEMPLATE_ID        = "17540bf2-5d77-4ac2-be34-ba89c728c60b"
  DELETE_ACCOUNT_TEMPLATE_ID       = "9a212a1d-5bfc-4e7f-80fa-033d3ae03a1c"
  PHONE_NUMBER_UPDATED_TEMPLATE_ID = "d12aaa12-1590-4d3d-b75e-e513d299b1b6"
  PASSWORD_UPDATED_TEMPLATE_ID     = "435cf040-2dfc-4d1c-838d-2f349c8d11f1"
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

logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]