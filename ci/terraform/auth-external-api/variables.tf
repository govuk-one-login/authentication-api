variable "shared_state_bucket" {
  type    = string
  default = "digital-identity-dev-tfstate"
}

variable "environment" {
  type = string
}

variable "deployer_role_arn" {
  default     = ""
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "aws_region" {
  default = "eu-west-2"
}
