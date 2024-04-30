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
