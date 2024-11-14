variable "role_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "extra_tags" {
  default     = {}
  type        = map(string)
  description = "Extra tags to apply to resources"
}

variable "policies_to_attach" {
  type        = list(string)
  default     = []
  description = "Policies to attach to the role"
}

variable "vpc_arn" {
  default = ""
  type    = string
}
