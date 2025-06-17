variable "shared_state_bucket" {
  type    = string
  default = "digital-identity-dev-tfstate"
}

variable "environment" {
  type = string
}

variable "deployer_role_arn" {
  default     = null
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "auth_ext_lambda_zip_file" {
  default     = "./artifacts/auth-external-api.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}

variable "aws_region" {
  default = "eu-west-2"
  type    = string
}

variable "enable_api_gateway_execution_request_tracing" {
  default     = false
  description = "Whether to enable capturing of requests/responses from API gateway runs (ONLY ENABLE IN NON-PROD ENVIRONMENTS)"
  type        = bool
}

variable "txma_account_id" {
  default = ""
  type    = string
}

variable "enable_api_gateway_execution_logging" {
  default     = true
  description = "Whether to enable logging of API gateway runs"
  type        = bool
}

variable "cloudwatch_log_retention" {
  default     = 30
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "logging_endpoint_arns" {
  type        = list(string)
  default     = []
  description = "Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to"
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

variable "lambda_min_concurrency" {
  default     = 0
  type        = number
  description = "The number of lambda instance to keep 'warm'"
}

variable "endpoint_memory_size" {
  default = 1536
  type    = number
}

variable "authentication_auth_callback_uri" {
  default     = ""
  type        = string
  description = "The redirect URI used by the orchestrator's auth callback lambda when calling the token endpoint. N.B. there is no actual redirect in the orchestration <-> authentication flow, but it is a part of OAuth2 formalities"
}

variable "orch_client_id" {
  default     = "orchestrationAuth"
  type        = string
  description = "The client ID used by the orchestrator in two situations: 1) when passing an authorize request to the authentication frontend - see OIDC module 2) when calling the authentication token endpoint - in this second case there is no real client registry or defined scopes, but it is a part of OAuth2 formalities."
}

variable "orch_to_auth_public_signing_key" {
  default     = ""
  type        = string
  description = "A hardcoded value for the public key corresponding to the KMS created in the OIDC module. It is used to validate the signature of a client_assertion JWT (orch<->auth token endpoint)"
}

variable "orch_stub_to_auth_public_signing_key" {
  default     = ""
  type        = string
  description = "A hardcoded value for the public key corresponding to the public key of the Orchestration stub. It should only be set in non-production environments. It is used to validate the signature of a client_assertion JWT (orch<->auth token endpoint)"
}

variable "orch_api_vpc_endpoint_id" {
  default     = ""
  type        = string
  description = "The ID of the Execute API Gateway vpc endpoint in the orchestration account"
}

locals {
  default_performance_parameters = {
    memory          = var.endpoint_memory_size
    concurrency     = var.lambda_min_concurrency
    max_concurrency = var.lambda_max_concurrency
    scaling_trigger = var.scaling_trigger
  }
}

variable "snapstart_enabled" {
  description = "The flag to enable AWS Lambda SnapStart for Lambdas, Make sure you set Provisoned_concurrency to 0 for the lambda to work with SnapStart"
  type        = bool
  default     = false
}

variable "vpc_environment" {
  description = "The name of the environment this environment is sharing the VPC , this var is only for Authdevs env and must be overide using Authdevs.tfvars, default value should be null always."
  type        = string
  default     = null
}

variable "new_auth_api_vpc_endpoint_id" {
  default     = ""
  type        = string
  description = "The ID of the Execute API Gateway vpc endpoint in the new Auth account"
}
