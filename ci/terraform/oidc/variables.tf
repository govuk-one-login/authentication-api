variable "oidc_api_lambda_zip_file" {
  default     = "../../../oidc-api/build/distributions/oidc-api.zip"
  description = "Location of the OIDC API Lambda ZIP file"
  type        = string
}

variable "frontend_api_lambda_zip_file" {
  default     = "../../../frontend-api/build/distributions/frontend-api.zip"
  description = "Location of the Frontend API Lambda ZIP file"
  type        = string
}

variable "client_registry_api_lambda_zip_file" {
  default     = "../../../client-registry-api/build/distributions/client-registry-api.zip"
  description = "Location of the client registry API Lambda ZIP file"
  type        = string
}

variable "lambda_warmer_zip_file" {
  default     = "../../../lambda-warmer/build/distributions/lambda-warmer.zip"
  description = "Location of the Lambda Warmer ZIP file"
  type        = string
}

variable "deployer_role_arn" {
  default     = ""
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

variable "environment" {
  type = string
}

variable "api_deployment_stage_name" {
  type    = string
  default = "test"
}

variable "api_base_url" {
  type    = string
  default = "http://localhost:8080"
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
  default = "1.0"
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

variable "service_domain_name" {
  default = "auth.ida.digital.cabinet-office.gov.uk"
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
  default     = false
  description = "Whether the service should ship its Lambda logs to the `logging_endpoint_arn`"
}

variable "logging_endpoint_arn" {
  type        = string
  default     = ""
  description = "Amazon Resource Name (ARN) for the endpoint to ship logs to"
}

variable "stub_rp_clients" {
  default     = []
  type        = list(object({ client_name : string, callback_urls : list(string), logout_urls : list(string) }))
  description = "The details of RP clients to provision in the Client table"
}

variable "aws_region" {
  default = "eu-west-2"
}

variable "keep_lambdas_warm" {
  default = true
  type    = bool
}

variable "reset_password_route" {
  type    = string
  default = "/reset-password?code="
}

variable "frontend_base_url" {
  type    = string
  default = ""
}

variable "dns_state_bucket" {
  type = string
}

variable "dns_state_key" {
  type = string
}

variable "dns_state_role" {
  type = string
}

variable "shared_state_bucket" {
  type = string
  default = ""
}

variable "shared_state_key" {
  type = string
  default = ""
}

variable "shared_state_role" {
  type = string
  default = ""
}

variable "authentication_security_group_id" {
  type = string
}

variable "authentication_subnet_ids" {
  type = list(string)
}

variable "lambda_iam_role_arn" {
  type = string
}

variable "lambda_iam_role_name" {
  type = string
}

variable "dynamo_sqs_lambda_iam_role_arn" {
  type = string
}

variable "dynamo_sqs_lambda_iam_role_name" {
  type = string
}

variable "sqs_lambda_iam_role_arn" {
  type = string
}

variable "sqs_lambda_iam_role_name" {
  type = string
}

variable "email_lambda_iam_role_arn" {
  type = string
}

variable "token_lambda_iam_role_arn" {
  type = string
}

variable "id_token_signing_key_alias_name" {
  type = string
}
