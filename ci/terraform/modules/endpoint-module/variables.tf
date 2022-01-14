variable "endpoint_name" {
  type = string
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
  type = string
}

variable "lambda_zip_file" {
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
  default = "java11"
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

variable "authentication_vpc_arn" {
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

variable "logging_endpoint_enabled" {
  type        = bool
  default     = false
  description = "Whether the Lambda should ship its logs to the `logging_endpoint_arn`"
}

variable "logging_endpoint_arn" {
  type        = string
  default     = ""
  description = "Amazon Resource Name (ARN) for the endpoint to ship logs to"
}

variable "use_localstack" {
  type = bool
}

variable "default_tags" {
  default     = {}
  type        = map(string)
  description = "Default tags to apply to all resources"
}

variable "keep_lambda_warm" {
  type    = bool
  default = true
}

variable "warmer_lambda_zip_file" {
  type    = string
  default = null
}

variable "warmer_handler_function_name" {
  type    = string
  default = null
}

variable "warmer_handler_environment_variables" {
  type    = map(string)
  default = null
}

variable "warmer_handler_runtime" {
  type    = string
  default = "java11"
}

variable "warmer_run_minutes" {
  type    = number
  default = 5
}

variable "warmer_delay_millis" {
  type    = number
  default = 200
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
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "lambda_log_alarm_threshold" {
  type        = number
  description = "The number of errors in a lambda logs before generating a Cloudwatch alarm"
  default     = 5
}

variable "lambda_env_vars_encryption_kms_key_arn" {
  type = string
}