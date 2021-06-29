resource "aws_dynamodb_table" "user_credentials_table" {
  name           = "${var.environment}-user-credentials"
  billing_mode   = "PROVISIONED"
  write_capacity = 5
  read_capacity  = 5
  hash_key       = "Email"

  attribute {
    name = "Email"
    type = "S"
  }

  attribute {
    name = "SubjectID"
    type = "S"
  }

  global_secondary_index {
    name               = "SubjectIDIndex"
    hash_key           = "SubjectID"
    write_capacity     = 5
    read_capacity      = 5
    projection_type    = "INCLUDE"
    non_key_attributes = ["Email"]
  }

  server_side_encryption {
    enabled = true
  }
}

resource "aws_dynamodb_table" "user_profile_table" {
  name           = "${var.environment}-user-profile"
  billing_mode   = "PROVISIONED"
  write_capacity = 5
  read_capacity  = 5
  hash_key       = "Email"

  attribute {
    name = "Email"
    type = "S"
  }

  attribute {
    name = "SubjectID"
    type = "S"
  }

  global_secondary_index {
    name               = "SubjectIDIndex"
    hash_key           = "SubjectID"
    write_capacity     = 5
    read_capacity      = 5
    projection_type    = "INCLUDE"
    non_key_attributes = ["Email"]
  }

  server_side_encryption {
    enabled = true
  }
}