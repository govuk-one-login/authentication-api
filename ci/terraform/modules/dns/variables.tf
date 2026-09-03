variable "aws_region" {
  type    = string
  default = "eu-west-2"
}

variable "dns_state_bucket" {
  type = string
}

variable "dns_state_key" {
  type = string
}

variable "environment" {
  type = string
}
