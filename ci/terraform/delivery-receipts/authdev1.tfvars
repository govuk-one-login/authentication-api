environment         = "authdev1"
common_state_bucket = "di-auth-development-tfstate"
vpc_environment     = "dev"

logging_endpoint_enabled = false
logging_endpoint_arns    = []

notify_template_map = {
  CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION_TEMPLATE_ID = "d253a170-8144-4471-b339-c35965c9298a"
  TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID            = "067548f2-420d-4da9-923f-ec9a941706cf"
}

lambda_max_concurrency          = 0
lambda_min_concurrency          = 0
delivery_receipts_use_snapstart = true
