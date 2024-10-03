variable "lambda_function_name" {
  type = string
}

variable "lambda_version" {
  type = string
}

variable "lambda_alias_name" {
  description = "alias of lambda which will be deployed by CodeDeploy"
  type        = string
}

variable "lambda_alias_version" {
  type = string
}

variable "environment" {
  type = string
}

variable "endpoint_name" {
  type = string
}
variable "aws_cli_command" {
  description = "Command to run as AWS CLI. May include extra arguments like region and profile."
  type        = string
  default     = "aws"
}

variable "get_deployment_sleep_timer" {
  description = "Adds additional sleep time to get-deployment command to avoid the service throttling"
  type        = number
  default     = 60
}

variable "force_deploy" {
  description = "Force deployment every time (even when nothing changes)"
  type        = bool
  default     = false
}

variable "interpreter" {
  description = "List of interpreter arguments used to execute deploy script, first arg is path"
  type        = list(string)
  default     = ["/bin/bash", "-c"]
}

variable "current_version" {
  description = "Current version of Lambda function version to deploy (can't be $LATEST)"
  type        = string
  default     = ""
}

variable "auto_rollback_events" {
  description = "List of event types that trigger a rollback. Supported types are DEPLOYMENT_FAILURE and DEPLOYMENT_STOP_ON_ALARM."
  type        = list(string)
  default     = ["DEPLOYMENT_FAILURE"]
}

variable "code_deploy_notification" {
  description = "Enable Notication for Code deployment failure"
  type        = bool
  default     = true
}

variable "skip_canary" {
  description = "Flag to skip cannary if [skip canary] or [canary skip], or [no canary] string is included in git merge commit message"
  type        = bool
  default     = false
}
