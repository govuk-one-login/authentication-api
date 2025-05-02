variable "aws_region" {
  default = "eu-west-2"
  type    = string
}

variable "deployer_role_arn" {
  default     = null
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

variable "allow_bulk_test_users" {
  type    = bool
  default = false
}

variable "utils_release_zip_file" {
  default     = "./artifacts/utils.zip"
  description = "Location of the Utils distribution ZIP file"
  type        = string
}

variable "shared_state_bucket" {
  type    = string
  default = "digital-identity-dev-tfstate"
}

variable "logging_endpoint_arns" {
  type        = list(string)
  default     = []
  description = "Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to"
}

variable "cloudwatch_log_retention" {
  default     = 30
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "terms_and_conditions" {
  type        = string
  default     = "1.13"
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
  default = 0
}

variable "bulk_user_email_max_audience_load_user_batch_size" {
  type    = number
  default = 0
}

variable "bulk_user_email_email_sending_enabled" {
  type    = string
  default = "false"
}

variable "bulk_user_email_send_schedule_enabled" {
  type    = bool
  default = false
}

variable "bulk_user_email_included_terms_and_conditions" {
  type    = string
  default = null
}

variable "bulk_user_email_send_mode" {
  type    = string
  default = "PENDING"
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

variable "performance_tuning" {
  type = map(object({
    memory : number,
    timeout : number,
  }))
  description = "A map of performance tuning parameters per lambda"
  default     = {}
}

variable "lambda_log_alarm_error_rate_threshold" {
  type        = number
  description = "The rate of errors in a lambda before generating a Cloudwatch alarm. Calculated by dividing the number of errors in a lambda divided by the number of invocations in a 15 minute period"
  default     = 1
}

variable "internal_sector_uri" {
  type    = string
  default = "undefined"
}

variable "email_check_results_writer_provisioned_concurrency" {
  description = "Provisioned concurrency for the email check results writer"
  type        = number
  default     = 1
}

variable "email_check_results_sqs_queue_arn" {
  description = "ARN of the SQS email results check queue"
  type        = string
}

variable "email_check_results_sqs_queue_encryption_key_arn" {
  description = "ARN of the CMK used for server side encryption on the SQS email results check queue"
  type        = string
}

variable "support_email_check_enabled" {
  default     = true
  type        = bool
  description = "Feature flag which toggles the Experian email check on and off"
}
