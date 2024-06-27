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
  default = "1.10"
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

variable "stub_rp_clients" {
  default     = []
  type        = list(object({ client_name : string, sector_identifier_uri : string, callback_urls : list(string), logout_urls : list(string), test_client : string, scopes : list(string), client_type : string, identity_verification_supported : string, one_login_service : bool, service_type : string }))
  description = "The details of RP clients to provision in the Client table"
}

variable "aws_region" {
  default = "eu-west-2"
}

variable "redis_node_size" {
  default = "cache.t2.small"
}

variable "provision_dynamo" {
  type    = bool
  default = false
}

variable "ipv_api_enabled" {
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
}

variable "tools_account_id" {
  description = "AWS Account for the corresponding tools account to this environment"
  type        = string
  default     = "706615647326"
}

variable "enforce_code_signing" {
  default     = true
  description = "Whether the code signing policy will reject unsigned code. (only set to false in sandpit environments)"
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
