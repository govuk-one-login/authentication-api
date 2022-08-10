variable "deployer_role_arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "lambda_zip_file" {
  default     = "../../../delivery-receipts-api/build/distributions/delivery-receipts-api.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}

variable "keep_lambdas_warm" {
  default = true
  type    = bool
}

variable "lambda_min_concurrency" {
  default     = 10
  type        = number
  description = "The number of lambda instance to keep 'warm'"
}

variable "common_state_bucket" {
  type = string
}

variable "environment" {
  type = string
}

variable "aws_endpoint" {
  type    = string
  default = null
}

variable "use_localstack" {
  type    = bool
  default = false
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

variable "aws_region" {
  default = "eu-west-2"
}

variable "cloudwatch_log_retention" {
  default     = 1
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "endpoint_memory_size" {
  default = 4096
  type    = number
}

variable "notify_template_map" {
  type = map(string)
  default = {
    VERIFY_EMAIL_TEMPLATE_ID                 = "b7dbb02f-941b-4d72-ad64-84cbe5d77c2e"
    RESET_PASSWORD_TEMPLATE_ID               = "0aaf3ae8-1825-4528-af95-3093eb13fda0"
    PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID  = "052d4e96-e6ca-4da2-b657-5649f28bd6c0"
    ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID = "a15995f7-94a3-4a1b-9da0-54b1a8b5cc12"
    RESET_PASSWORD_WITH_CODE_TEMPLATE_ID     = "503a8096-d22e-49dc-9f81-007cad156f01"
    EMAIL_UPDATED_TEMPLATE_ID                = "0a200a63-97b2-4920-bc40-48e9a9e1121e"
    DELETE_ACCOUNT_TEMPLATE_ID               = "0706adcc-b593-4d2d-afa6-c3da7149e426"
    PHONE_NUMBER_UPDATED_TEMPLATE_ID         = "8274a2a3-5121-4630-a27e-e8578f8cba59"
    PASSWORD_UPDATED_TEMPLATE_ID             = "323ebef4-cfa7-414f-bfba-1db324acdd66"
    VERIFY_PHONE_NUMBER_TEMPLATE_ID          = "7dd388f1-e029-4fe7-92ff-18496dcb53e9"
    MFA_SMS_TEMPLATE_ID                      = "97b956c8-9a12-451a-994b-5d51741b63d4"
  }
}
