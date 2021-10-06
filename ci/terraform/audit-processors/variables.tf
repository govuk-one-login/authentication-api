variable "deployer_role_arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "environment" {
  type = string
}

variable "aws_region" {
  type    = string
  default = "eu-west-2"
}

variable "use_localstack" {
  type    = bool
  default = false
}

variable "aws_endpoint" {
  type    = string
  default = null
}

variable "shared_state_bucket" {
  type = string
}