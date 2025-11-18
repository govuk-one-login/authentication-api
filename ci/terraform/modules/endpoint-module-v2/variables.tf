variable "endpoint_name" {
  description = "The name of the endpoint, used for naming resources"
  type        = string
}


variable "endpoint_name_sanitized" {
  description = "The name of the endpoint, required if endpoint_name contains a period"
  type        = string
  default     = null
}


variable "path_part" {
  type = string
}

variable "method_request_parameters" {
  type    = map(bool)
  default = {}
}

variable "create_endpoint" {
  type    = bool
  default = true
}

variable "api_key_required" {
  type    = bool
  default = false
}

variable "integration_request_parameters" {
  type    = map(string)
  default = {}
}

variable "endpoint_method" {
  type = list(string)
}

variable "source_bucket" {
  type = string
}

variable "lambda_zip_file" {
  type = string
}

variable "lambda_zip_file_version" {
  type = string
}

variable "handler_function_name" {
  type = string
}

variable "handler_environment_variables" {
  type = map(string)
}

variable "handler_runtime" {
  type    = string
  default = "java17"
}

variable "rest_api_id" {
  type = string
}

variable "root_resource_id" {
  type = string
}

variable "execution_arn" {
  type = string
}

variable "environment" {
  type = string
}

variable "security_group_ids" {
  type        = list(string)
  description = "The list of security group IDs to apply to the lambda"
}

variable "subnet_id" {
  type        = list(string)
  description = "The id of the subnets for the lambda"
}

variable "lambda_role_arn" {
  type = string
}

variable "logging_endpoint_arns" {
  type        = list(string)
  default     = []
  description = "Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to"
}

variable "extra_tags" {
  default     = {}
  type        = map(string)
  description = "Extra tags to apply to resources"
}

variable "authorizer_id" {
  type    = string
  default = null
}

variable "cloudwatch_key_arn" {
  type        = string
  description = "The ARN of the KMS key to use log encryption"
}

variable "cloudwatch_log_retention" {
  default     = 30
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "lambda_log_alarm_threshold" {
  type        = number
  description = "The number of errors in a lambda logs before generating a Cloudwatch alarm"
  default     = 5
}

variable "lambda_log_alarm_error_rate_threshold" {
  type        = number
  description = "The rate of errors in a lambda before generating a Cloudwatch alarm. Calculated by dividing the number of errors in a lambda divided by the number of invocations in a 60 second period"
  default     = 10
}

variable "lambda_error_rate_alarm_disabled" {
  type    = bool
  default = false
}

variable "lambda_env_vars_encryption_kms_key_arn" {
  type = string
}

variable "code_signing_config_arn" {
  default = null
  type    = string
}

variable "memory_size" {
  type = number
}

variable "provisioned_concurrency" {
  default = 0
  type    = number
}

variable "max_provisioned_concurrency" {
  default = 5
  type    = number
}

variable "scaling_trigger" {
  default = 0.7
  type    = number
}

variable "slack_event_topic_arn" {
  description = "The ARN of the slack event topic"
  type        = string
}

variable "account_alias" {
  description = "The 'friendly-name' of the AWS account, eg. di-auth-development"
  type        = string
}

variable "dynatrace_secret" {
  description = "JSON decoded dynatrace secret"

  type = object({
    JAVA_LAYER = string

    DT_CONNECTION_AUTH_TOKEN     = string
    DT_CONNECTION_BASE_URL       = string
    DT_CLUSTER_ID                = string
    DT_TENANT                    = string
    DT_LOG_COLLECTION_AUTH_TOKEN = string
  })
  sensitive = true
}

variable "snapstart" {
  type    = bool
  default = false
}

variable "runbook_link" {
  description = "A link that is appended to alarm descriptions that should open a page describing how to triage and handle the alarm"
  type        = string
  default     = null
}

variable "lambda_error_alarm_disabled" {
  type    = bool
  default = false
}
