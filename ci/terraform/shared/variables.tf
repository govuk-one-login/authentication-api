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

variable "terms_and_conditions" {
  type    = string
  default = "1.13"
}

variable "logging_endpoint_arns" {
  type        = list(string)
  default     = []
  description = "Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to"
}

variable "stub_rp_clients" {
  default     = []
  type        = list(object({ client_name : string, at_client : bool, sector_identifier_uri : string, callback_urls : list(string), logout_urls : list(string), test_client : string, scopes : list(string), client_type : string, one_login_service : bool, service_type : string, max_age_enabled : bool, back_channel_logout_uri : optional(string) }))
  description = "The details of RP clients to provision in the Client table"
  validation {
    condition     = length(var.stub_rp_clients) > 0
    error_message = "At least one RP client must be defined"
  }
  validation {
    condition     = length([for client in var.stub_rp_clients : client if client.at_client == true]) == 1
    error_message = "Exactly one RP client must be marked as the acceptance test client, with `at_client = true`"
  }
}

variable "orch_stub_deployed" {
  type        = bool
  default     = true
  description = "Whether the orchestration stub has been deployed"
}

variable "aws_region" {
  default = "eu-west-2"
  type    = string
}

variable "redis_node_size" {
  default = "cache.t2.small"
  type    = string
}

variable "provision_dynamo" {
  type    = bool
  default = false
}

variable "dynamo_default_read_capacity" {
  type    = number
  default = 20
}

variable "dynamo_default_write_capacity" {
  type    = number
  default = 20
}

variable "dynamo_deletion_protection_enabled" {
  type    = bool
  default = true
}

variable "test_client_email_allowlist" {
  type = string
}

variable "password_pepper" {
  description = "Added to migrated passwords before hashed"
  type        = string
  default     = null
}

variable "common_state_bucket" {
  type    = string
  default = "digital-identity-dev-tfstate"
}

variable "di_tools_signing_profile_version_arn" {
  description = "The AWS Signer profile version to use from the `di-tools-prod` account"
  default     = "arn:aws:signer:eu-west-2:114407264696:/signing-profiles/di_auth_lambda_signing_20220215170204371800000001/zLiNn2Hi1I"
  type        = string
}

variable "tools_account_id" {
  description = "AWS Account for the corresponding tools account to this environment"
  type        = string
  default     = "706615647326"
}

variable "enforce_code_signing" {
  default     = true
  description = "Whether the code signing policy will reject unsigned code. (only set to false in sandpit environments)"
  type        = bool
}

variable "enable_user_profile_stream" {
  default     = true
  type        = bool
  description = "Whether the User Profile DynamoDB table should have streaming turned on (this is consumed by Experian Phone Check lambda in a separate repo)"
}

variable "auth_check_account_id" {
  type        = string
  description = "Account id of the auth check aws account"
}

variable "orchestration_account_id" {
  type        = string
  description = "Account id of the corresponding Orchestration aws account"
  default     = ""
}

variable "dlq_alarm_threshold" {
  default     = 1
  type        = number
  description = "The number of messages on a DLQ before a Cloudwatch alarm is generated"
}

variable "orch_privatesub_cidr_blocks" {
  type        = list(string)
  description = "Orchestration private subnet cidr blocks"
  default     = []
}

variable "orch_protectedsub_cidr_blocks" {
  type        = list(string)
  description = "Orchestration protected subnet cidr blocks"
  default     = []
}

variable "auth_new_account_id" {
  type        = string
  description = "Account id of the auth new frontend"
  default     = ""
}

variable "vpc_environment" {
  description = "The name of the environment this environment is sharing the VPC , this var is only for Authdevs env and must be overide using Authdevs.tfvars, default value should be null always."
  type        = string
  default     = null
}

variable "new_auth_protectedsub_cidr_blocks" {
  type        = list(string)
  default     = []
  description = "New Auth equivalent environment protected subnets"
}

variable "new_auth_privatesub_cidr_blocks" {
  type        = list(string)
  default     = []
  description = "New Auth equivalent environment private subnets"
}

variable "provision_test_client_secret" {
  type    = bool
  default = false
}
