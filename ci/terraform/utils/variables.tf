variable "aws_region" {
  default = "eu-west-2"
}

variable "deployer_role_arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
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

variable "use_localstack" {
  type    = bool
  default = false
}

variable "allow_bulk_test_users" {
  type    = bool
  default = false
}

variable "utils_release_zip_file" {
  default     = "../../../utils/build/distributions/utils.zip"
  description = "Location of the Utils distribution ZIP file"
  type        = string
}

variable "shared_state_bucket" {
  type    = string
  default = "digital-identity-dev-tfstate"
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

variable "cloudwatch_log_retention" {
  default     = 5
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "terms_and_conditions" {
  type        = string
  default     = "1.6"
  description = "The latest Terms and Conditions version number"
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
    TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID = "067548f2-420d-4da9-923f-ec9a941706cf"
  }
}

variable "bulk_user_email_batch_query_limit" {
  type    = number
  default = null
}

variable "bulk_user_email_max_batch_count" {
  type    = number
  default = null
}

variable "bulk_user_email_batch_pause_duration" {
  type    = number
  default = null
}

variable "bulk_user_email_max_audience_load_user_count" {
  type    = number
  default = null
}

variable "bulk_user_email_email_sending_enabled" {
  type    = string
  default = "false"
}

variable "bulk_user_email_send_schedule_enabled" {
  type    = bool
  default = false
}

variable "bulk_user_email_send_schedule_expression" {
  type        = string
  description = "Run at 15:00 every Friday in 2049.  Designed not to trigger, replace with desired expression."
  default     = "cron(0 15 ? * FRI 2049)"
}

variable "bulk_user_email_audience_loader_schedule_enabled" {
  type    = bool
  default = false
}

variable "bulk_user_email_audience_loader_schedule_expression" {
  type        = string
  description = "Run at 15:00 every Friday in 2049.  Designed not to trigger, replace with desired expression."
  default     = "cron(0 13 ? * FRI 2049)"
}

variable "txma_account_id" {
  default = ""
  type    = string
}

variable "performance_tuning" {
  type = map(object({
    memory : number,
    timeout : number,
  }))
  description = "A map of performance tuning parameters per lambda"
  default     = {}
}