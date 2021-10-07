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

variable "notify_template_map" {
  type = map(string)
  default = {
    VERIFY_EMAIL_TEMPLATE_ID                 = "b7dbb02f-941b-4d72-ad64-84cbe5d77c2e"
    VERIFY_PHONE_NUMBER_TEMPLATE_ID          = "7dd388f1-e029-4fe7-92ff-18496dcb53e9"
    MFA_SMS_TEMPLATE_ID                      = "7dd388f1-e029-4fe7-92ff-18496dcb53e9"
    RESET_PASSWORD_TEMPLATE_ID               = "0aaf3ae8-1825-4528-af95-3093eb13fda0"
    PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID  = "052d4e96-e6ca-4da2-b657-5649f28bd6c0"
    ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID = "a15995f7-94a3-4a1b-9da0-54b1a8b5cc12"
  }
}

variable "environment" {
  type = string
}

variable "api_base_url" {
  type    = string
  default = "http://localhost:8080"
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

variable "external_redis_host" {
  type    = string
  default = "redis"
}

variable "terms_and_conditions" {
  type    = string
  default = "1.0"
}

variable "external_redis_port" {
  type    = number
  default = 6379
}

variable "external_redis_password" {
  type    = string
  default = null
}

variable "localstack_endpoint" {
  type    = string
  default = "http://localhost:45678/"
}


variable "redis_use_tls" {
  type    = string
  default = "true"
}

variable "service_domain_name" {
  default = "auth.ida.digital.cabinet-office.gov.uk"
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
  default     = false
  description = "Whether the service should ship its Lambda logs to the `logging_endpoint_arn`"
}

variable "logging_endpoint_arn" {
  type        = string
  default     = ""
  description = "Amazon Resource Name (ARN) for the endpoint to ship logs to"
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
  default = "/reset-password?code="
}

variable "frontend_base_url" {
  type    = string
  default = null
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

variable "account_management_url" {
  type = string
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
  default     = 10
  type        = number
  description = "The number of lambda instance to keep 'warm'"
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