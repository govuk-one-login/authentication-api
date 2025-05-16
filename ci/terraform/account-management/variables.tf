variable "deployer_role_arn" {
  default     = null
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
    AM_VERIFY_EMAIL_TEMPLATE_ID        = "2564a2fe-df04-43df-b086-08831b1034d7"
    AM_VERIFY_PHONE_NUMBER_TEMPLATE_ID = "86fbfd12-e428-4579-b0ee-42ba2b840eac"
    EMAIL_UPDATED_TEMPLATE_ID          = "0a200a63-97b2-4920-bc40-48e9a9e1121e"
    DELETE_ACCOUNT_TEMPLATE_ID         = "0706adcc-b593-4d2d-afa6-c3da7149e426"
    PHONE_NUMBER_UPDATED_TEMPLATE_ID   = "8274a2a3-5121-4630-a27e-e8578f8cba59"
    PASSWORD_UPDATED_TEMPLATE_ID       = "323ebef4-cfa7-414f-bfba-1db324acdd66"
  }
}

variable "environment" {
  type = string
}

variable "aws_region" {
  default = "eu-west-2"
  type    = string
}

variable "aws_endpoint" {
  type    = string
  default = null
}

variable "aws_dynamodb_endpoint" {
  type    = string
  default = null
}

variable "enable_api_gateway_execution_logging" {
  default     = true
  description = "Whether to enable logging of API gateway runs"
  type        = bool
}

variable "enable_api_gateway_execution_request_tracing" {
  default     = false
  description = "Whether to enable capturing of requests/responses from API gateway runs (ONLY ENABLE IN NON-PROD ENVIRONMENTS)"
  type        = bool
}

variable "lambda_zip_file" {
  default     = "./artifacts/account-management-api.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}

variable "logging_endpoint_arns" {
  type        = list(string)
  default     = []
  description = "Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to"
}

variable "redis_node_size" {
  default = "cache.t2.micro"
  type    = string
}

variable "common_state_bucket" {
  type = string
}

variable "cloudwatch_log_retention" {
  default     = 30
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "dlq_alarm_threshold" {
  default     = 1
  type        = number
  description = "The number of messages on a DLQ before a Cloudwatch alarm is generated"
}

variable "lambda_min_concurrency" {
  default     = 0
  type        = number
  description = "The number of lambda instance to keep 'warm'"
}

variable "contact_us_link_route" {
  type    = string
  default = "contact-gov-uk-one-login"
}

variable "endpoint_memory_size" {
  default = 1536
  type    = number
}

variable "internal_sector_uri" {
  type    = string
  default = "undefined"
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
  default = 0
  type    = number
}

variable "scaling_trigger" {
  default = 0.6
  type    = number
}

variable "txma_account_id" {
  default = ""
  type    = string
}

variable "lockout_duration" {
  type    = number
  default = 900
}

variable "otp_code_ttl_duration" {
  type    = number
  default = 900
}

variable "email_acct_creation_otp_code_ttl_duration" {
  type    = number
  default = 7200
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

variable "support_email_check_enabled" {
  default     = true
  type        = bool
  description = "Feature flag which toggles the Experian email check on and off"
}

variable "legacy_account_deletion_topic_arn" {
  type        = string
  description = "SNS ARN for the account deletion topic owned by Home for use with the manual account deletion lambda. A dev topic is created if this value is not provided."
  default     = null
}

variable "legacy_account_deletion_topic_key_arn" {
  type        = string
  description = "KMS ARN for the key for the account deletion topic owned by Home for use with the manual account deletion lambda."
  default     = ""
}

locals {
  default_performance_parameters = {
    memory          = var.endpoint_memory_size
    concurrency     = var.lambda_min_concurrency
    max_concurrency = var.lambda_max_concurrency
    scaling_trigger = var.scaling_trigger
  }
}

variable "openapi_spec_filename" {
  type        = string
  default     = "openapi.yaml"
  description = "The name of the OpenAPI spec file, located within this module."
}
variable "vpc_environment" {
  description = "The name of the environment this environment is sharing the VPC , this var is only for Authdevs env and must be overide using Authdevs.tfvars, default value should be null always."
  type        = string
  default     = null
}

variable "mfa_method_management_api_enabled" {
  description = "Feature flag for the method management api, enabling us to manage multiple mfa methods for a user"
  type        = bool
  default     = false
}

variable "account_intervention_service_uri" {
  default = ""
  type    = string
}

variable "ais_call_in_authenticate_enabled" {
  description = "Feature flag to call AIS in the /authenticate handler when a user reverifies their password"
  type        = bool
  default     = false
}

variable "home_vpc_endpoint_id" {
  description = "The execute API vpc endpoint ID of Home AWS account to give execute access on method mgmt API"
  type        = string
  default     = ""
}

variable "am_api_fms_tag_value" {
  description = "The value of the FMS tag to be applied to the account management API Gateway"
  type        = string
  default     = "accountmanagement"
}

variable "notify_test_destinations" {
  description = "The list of notify destinations that are allowed to write their otp codes to S3."
  type        = string
  default     = ""
}
