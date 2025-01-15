variable "environment" {
  description = "The environment this layer is for"
  type        = string
}
variable "layer_name" {
  description = "The name of the layer. var.environment will be prefixed to this name"
  type        = string
}
variable "zip_file_path" {
  description = "Location of the layer zip file on the local filesystem"
  type        = string
}
