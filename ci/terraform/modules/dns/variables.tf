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

variable "dns_state_role" {
  type = string
}

variable "environment" {
  type = string
}

variable "is_localstack" {
  type = bool
  default = false
}

variable "is_sandpit" {
  type = bool
  default = false
}
