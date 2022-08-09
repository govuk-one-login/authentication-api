variable "environment" {
  type = string
}

variable "default_tags" {
  default     = {}
  type        = map(string)
  description = "Default tags to apply to all resources"
}

variable "txma_account_id" {
  type        = string
  description = "Account id of the corresponding TxMA processor"
}