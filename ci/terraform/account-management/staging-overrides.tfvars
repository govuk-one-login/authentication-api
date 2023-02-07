lambda_max_concurrency = 3
lambda_min_concurrency = 1
endpoint_memory_size   = 1024
scaling_trigger        = 0.6

logging_endpoint_arns = [
  "arn:aws:logs:eu-west-2:885513274347:destination:csls_cw_logs_destination_prodpython"
]

notify_template_map = {
  VERIFY_EMAIL_TEMPLATE_ID         = "09f29c9a-3f34-4a56-88f5-8197aede7f85"
  VERIFY_PHONE_NUMBER_TEMPLATE_ID  = "8babad52-0e2e-443a-8a5a-c296dc1696cc"
  EMAIL_UPDATED_TEMPLATE_ID        = "22aac1ce-38c7-45f5-97b2-26ac1a54a235"
  DELETE_ACCOUNT_TEMPLATE_ID       = "1540bdda-fdff-4297-b627-92102e061bfa"
  PHONE_NUMBER_UPDATED_TEMPLATE_ID = "8907d080-e69c-42c6-8cf5-54ca1558a2e4"
  PASSWORD_UPDATED_TEMPLATE_ID     = "ebf3730c-0769-462b-ab39-7d9a7439bac1"
}