variable "oidc_api_lambda_zip_file" {
  default     = "../../../oidc-api/build/distributions/oidc-api.zip"
  description = "Location of the OIDC API Lambda ZIP file"
  type        = string
}

variable "frontend_api_lambda_zip_file" {
  default     = "../../../frontend-api/build/distributions/frontend-api.zip"
  description = "Location of the Frontend API Lambda ZIP file"
  type        = string
}

variable "client_registry_api_lambda_zip_file" {
  default     = "../../../client-registry-api/build/distributions/client-registry-api.zip"
  description = "Location of the client registry API Lambda ZIP file"
  type        = string
}

variable "ipv_api_lambda_zip_file" {
  default     = "../../../ipv-api/build/distributions/ipv-api.zip"
  description = "Location of the ipv API Lambda ZIP file"
  type        = string
}

variable "doc_checking_app_api_lambda_zip_file" {
  default     = "../../../doc-checking-app-api/build/distributions/doc-checking-app-api.zip"
  description = "Location of the doc checking app API Lambda ZIP file"
  type        = string
}

variable "lambda_warmer_zip_file" {
  default     = "../../../lambda-warmer/build/distributions/lambda-warmer.zip"
  description = "Location of the Lambda Warmer ZIP file"
  type        = string
}

variable "deployer_role_arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "notify_api_key" {
  description = "The API key required to communicate with Notify"
  type        = string
}

variable "notify_url" {
  type    = string
  default = null
}

variable "notify_test_destinations" {
  type    = string
  default = null
}

variable "notify_template_map" {
  type = map(string)
  default = {
    VERIFY_EMAIL_TEMPLATE_ID                 = "b7dbb02f-941b-4d72-ad64-84cbe5d77c2e"
    VERIFY_PHONE_NUMBER_TEMPLATE_ID          = "7dd388f1-e029-4fe7-92ff-18496dcb53e9"
    MFA_SMS_TEMPLATE_ID                      = "97b956c8-9a12-451a-994b-5d51741b63d4"
    RESET_PASSWORD_TEMPLATE_ID               = "0aaf3ae8-1825-4528-af95-3093eb13fda0"
    PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID  = "052d4e96-e6ca-4da2-b657-5649f28bd6c0"
    ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID = "a15995f7-94a3-4a1b-9da0-54b1a8b5cc12"
    RESET_PASSWORD_WITH_CODE_TEMPLATE_ID     = "503a8096-d22e-49dc-9f81-007cad156f01"
  }
}

variable "environment" {
  type = string
}

variable "aws_endpoint" {
  type    = string
  default = null
}

variable "aws_dynamodb_endpoint" {
  type    = string
  default = null
}

variable "lambda_dynamo_endpoint" {
  type        = string
  default     = "http://dynamodb:8000"
  description = "The endpoint that the Lambda must use to connect to DynamoDB API. This may or may not be the same as aws_dynamodb_endpoint"
}

variable "use_localstack" {
  type    = bool
  default = false
}

variable "terms_and_conditions" {
  type    = string
  default = "1.1"
}

variable "localstack_endpoint" {
  type    = string
  default = "http://localhost:45678/"
}


variable "redis_use_tls" {
  type    = string
  default = "true"
}

variable "enable_api_gateway_execution_logging" {
  default     = true
  description = "Whether to enable logging of API gateway runs"
}

variable "enable_api_gateway_execution_request_tracing" {
  default     = false
  description = "Whether to enable capturing of requests/responses from API gateway runs (ONLY ENABLE IN NON-PROD ENVIRONMENTS)"
}

variable "logging_endpoint_enabled" {
  type        = bool
  default     = true
  description = "Whether the service should ship its Lambda logs to the `logging_endpoint_arn`"
}

variable "logging_endpoint_arn" {
  type        = string
  default     = ""
  description = "Amazon Resource Name (ARN) for the endpoint to ship logs to"
}

variable "logging_endpoint_arns" {
  type        = list(string)
  default     = []
  description = "Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to"
}

variable "stub_rp_clients" {
  default     = []
  type        = list(object({ client_name : string, callback_urls : list(string), logout_urls : list(string) }))
  description = "The details of RP clients to provision in the Client table"
}

variable "aws_region" {
  default = "eu-west-2"
}

variable "keep_lambdas_warm" {
  default = true
  type    = bool
}

variable "reset_password_route" {
  type    = string
  default = "reset-password?code="
}

variable "blocked_email_duration" {
  type    = number
  default = 900
}

variable "contact_us_link_route" {
  type    = string
  default = "contact-us"
}

variable "dns_state_bucket" {
  type = string
}

variable "dns_state_key" {
  type = string
}

variable "dns_state_role" {
  type = string
}

variable "gov_uk_accounts_url" {
  type    = string
  default = "https://www.gov.uk/account"
}

variable "shared_state_bucket" {
  type = string
}

variable "cloudwatch_log_retention" {
  default     = 1
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "lambda_min_concurrency" {
  default     = 20
  type        = number
  description = "The number of lambda instance to keep 'warm'"
}

variable "dlq_alarm_threshold" {
  default     = 1
  type        = number
  description = "The number of messages on a DLQ before a Cloudwatch alarm is generated"
}

variable "waf_alarm_blocked_reqeuest_threshold" {
  default     = 1000
  type        = number
  description = "The number of blocked requests caught by the WAF before a Cloudwatch alarm is generated"
}

variable "test_client_verify_email_otp" {
  type = string
}

variable "test_client_verify_phone_number_otp" {
  type = string
}

variable "test_clients_enabled" {
  type    = string
  default = "false"
}

variable "client_registry_api_enabled" {
  default = true
}

variable "ipv_api_enabled" {
  default = false
}

variable "ipv_capacity_allowed" {
  default = false
}

variable "ipv_authorisation_uri" {
  type    = string
  default = "undefined"
}

variable "ipv_authorisation_callback_uri" {
  type    = string
  default = "undefined"
}

variable "ipv_authorisation_client_id" {
  type    = string
  default = "undefined"
}

variable "ipv_audience" {
  type    = string
  default = "undefined"
}

variable "ipv_backend_uri" {
  type    = string
  default = "undefined"
}

variable "ipv_sector" {
  type    = string
  default = "undefined"
}

variable "endpoint_memory_size" {
  default = 4096
  type    = number
}

variable "spot_enabled" {
  default = false
  type    = bool
}

variable "spot_queue_url" {
  default = "undefined"
  type    = string
}

variable "identity_trace_logging_enabled" {
  default = false
  type    = bool
}

variable "ipv_auth_public_encryption_key" {
  type    = string
  default = "undefined"
}

variable "doc_app_authorisation_uri" {
  type    = string
  default = "undefined"
}

variable "doc_app_authorisation_callback_uri" {
  type    = string
  default = "undefined"
}

variable "doc_app_authorisation_client_id" {
  type    = string
  default = "undefined"
}

variable "doc_app_api_enabled" {
  type    = bool
  default = false
}

variable "doc_app_domain" {
  type    = string
  default = "undefined"
}

variable "doc_app_backend_uri" {
  type        = string
  default     = ""
  description = "The base URL of the Doc App CRI API (to be used with the token endpoint and protected resource)"
}

variable "doc_app_cri_data_endpoint" {
  type        = string
  default     = ""
  description = "The endpoint path to the protected resource on the Doc App CRI (this is appended to the doc_app_backend_uri variable)"
}

variable "doc_app_encryption_key_id" {
  type    = string
  default = "undefined"
}

variable "doc_app_jwks_endpoint" {
  type    = string
  default = "undefined"
}

variable "spot_account_number" {
  type        = string
  default     = "undefined"
  description = "The AWS account number for SPOT"
}

variable "spot_response_queue_arn" {
  type        = string
  default     = "undefined"
  description = "The ARN for the SPOT response queue"
}

variable "spot_response_queue_kms_arn" {
  type        = string
  default     = "undefined"
  description = "The ARN for the KMS key used by the SPOT response queue"
}

variable "performance_tuning" {
  type = map(object({
    memory : number,
    concurrency : number,
    max_concurrency : number,
    scaling_trigger : number,
  }))
  description = "A map of performance tuning parameters per lambda"
  default     = {}
}

variable "lambda_max_concurrency" {
  default = 5
}

variable "scaling_trigger" {
  default = 0.7
}

variable "use_robots_txt" {
  default = true
  type    = bool
}

variable "txma_account_id" {
  default = ""
  type    = string
}

locals {
  default_performance_parameters = {
    memory          = var.endpoint_memory_size
    concurrency     = var.keep_lambdas_warm ? 0 : var.lambda_min_concurrency
    max_concurrency = var.lambda_max_concurrency
    scaling_trigger = var.scaling_trigger
  }
}
