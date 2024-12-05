variable "role_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "default_tags" {
  default     = {}
  type        = map(string)
  description = "Default tags to apply to all resources"
}

variable "policy_documents_to_attach" {
  type        = map(list(string))
  default     = {}
  description = "Policy documents to combine and attach to the role"

  validation {
    condition     = !contains(keys(var.policy_documents_to_attach), "base")
    error_message = "policy_documents_to_attach cannot contain a key named 'base'"
  }
  validation {
    condition     = length(keys(var.policy_documents_to_attach)) <= 20
    error_message = "policy_documents_to_attach cannot contain more than 20 keys"
  }
}

variable "vpc_arn" {
  default = ""
  type    = string
}
