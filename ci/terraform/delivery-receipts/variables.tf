variable "deployer_role_arn" {
  default     = null
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "lambda_zip_file" {
  default     = "./artifacts/delivery-receipts-api.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}

variable "common_state_bucket" {
  type    = string
  default = "digital-identity-dev-tfstate"
}

variable "environment" {
  type = string
}

variable "aws_endpoint" {
  type    = string
  default = null
}

variable "enable_api_gateway_execution_logging" {
  default     = true
  description = "Whether to enable logging of API gateway runs"
  type        = bool
}

variable "logging_endpoint_arns" {
  type        = list(string)
  default     = []
  description = "Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to"
}

variable "aws_region" {
  default = "eu-west-2"
  type    = string
}

variable "cloudwatch_log_retention" {
  default     = 30
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "endpoint_memory_size" {
  default = 1536
  type    = number
}

variable "notify_template_map" {
  type = map(string)
  default = {
    VERIFY_EMAIL_TEMPLATE_ID                               = "b7dbb02f-941b-4d72-ad64-84cbe5d77c2e"
    RESET_PASSWORD_TEMPLATE_ID                             = "0aaf3ae8-1825-4528-af95-3093eb13fda0"
    PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID                = "052d4e96-e6ca-4da2-b657-5649f28bd6c0"
    PASSWORD_RESET_CONFIRMATION_SMS_TEMPLATE_ID            = "ee9928fb-c716-4409-acd7-9b93fc02d0f8"
    ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID               = "a15995f7-94a3-4a1b-9da0-54b1a8b5cc12"
    RESET_PASSWORD_WITH_CODE_TEMPLATE_ID                   = "503a8096-d22e-49dc-9f81-007cad156f01"
    EMAIL_UPDATED_TEMPLATE_ID                              = "0a200a63-97b2-4920-bc40-48e9a9e1121e"
    DELETE_ACCOUNT_TEMPLATE_ID                             = "0706adcc-b593-4d2d-afa6-c3da7149e426"
    PHONE_NUMBER_UPDATED_TEMPLATE_ID                       = "8274a2a3-5121-4630-a27e-e8578f8cba59"
    PASSWORD_UPDATED_TEMPLATE_ID                           = "323ebef4-cfa7-414f-bfba-1db324acdd66"
    VERIFY_PHONE_NUMBER_TEMPLATE_ID                        = "7dd388f1-e029-4fe7-92ff-18496dcb53e9"
    MFA_SMS_TEMPLATE_ID                                    = "97b956c8-9a12-451a-994b-5d51741b63d4"
    AM_VERIFY_EMAIL_TEMPLATE_ID                            = "2564a2fe-df04-43df-b086-08831b1034d7"
    AM_VERIFY_PHONE_NUMBER_TEMPLATE_ID                     = "86fbfd12-e428-4579-b0ee-42ba2b840eac"
    VERIFY_CHANGE_HOW_GET_SECURITY_CODES_TEMPLATE_ID       = "31259695-e0b8-4c1f-8392-995d5a3b6978"
    CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION_TEMPLATE_ID = "10b2ebeb-16fb-450a-8dc3-5f94d2b7029f"
    TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID            = "067548f2-420d-4da9-923f-ec9a941706cf"
    REPORT_SUSPICIOUS_ACTIVITY_EMAIL_TEMPLATE_ID           = "2b3170b5-159e-457f-a282-f30f6006dc32"
    BACKUP_METHOD_ADDED_TEMPLATE_ID                        = "2abd5f54-15b6-4957-b4d3-f310f2437b9f"
    CHANGED_AUTHENTICATOR_APP_TEMPLATE_ID                  = "b0bb3667-985b-428c-9eb3-6b778b50fb6b"
    CHANGED_DEFAULT_MFA_TEMPLATE_ID                        = "ab62d5fa-79a8-4dba-beb0-283118d2450f"
    SWITCHED_MFA_METHODS_TEMPLATE_ID                       = "be78564b-b9a6-4b3d-b438-7b30e45caf54"
  }
}

variable "vpc_environment" {
  description = "The name of the environment this environment is sharing the VPC , this var is only for Authdevs env and must be overide using Authdevs.tfvars, default value should be null always."
  type        = string
  default     = null
}
