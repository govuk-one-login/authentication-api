variable "lambda_zip_file_path" {
  description = "file path to the lambda zip file"
  type        = string

  validation {
    condition     = can(regex(".*\\.zip", var.lambda_zip_file_path))
    error_message = "lambda_zip_file must be a zip file"
  }
  validation {
    condition     = fileexists(var.lambda_zip_file_path)
    error_message = "lambda_zip_file must exist"
  }
}

variable "java_module_name" {
  description = "The name of the java module this is a release for"
  type        = string
}

variable "bucket" {
  description = "The S3 bucket to upload the lambda zip file to"
  type        = string
}

variable "key" {
  description = "The S3 key to upload the lambda zip file to"
  type        = string
}

variable "server_side_encryption" {
  description = "The server side encryption to use for the uploaded object"
  type        = string
  default     = "AES256"
}
