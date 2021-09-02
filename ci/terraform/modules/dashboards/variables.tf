variable "api_gateway_name" {
  type        = string
  description = "The endpoint that will be monitored by the dashboard"
}

variable "use_localstack" {
  type = bool
}