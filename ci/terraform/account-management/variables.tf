variable "deployer_role_arn" {
  default     = null
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "environment" {
  type = string
}

variable "aws_region" {
  default = "eu-west-2"
  type    = string
}

variable "aws_endpoint" {
  type    = string
  default = null
}

variable "redis_node_size" {
  default = "cache.t2.micro"
  type    = string
}

variable "common_state_bucket" {
  type = string
}

variable "vpc_environment" {
  description = "The name of the environment this environment is sharing the VPC, this var is only for Authdevs env and must be overide using Authdevs.tfvars, default value should be null always."
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
