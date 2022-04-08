data "aws_dynamodb_table" "user_credential_table" {
  name = "${var.environment}-user-credentials"
}

data "aws_dynamodb_table" "user_profile_table" {
  name = "${var.environment}-user-profile"
}

resource "time_static" "create_date" {
  for_each = { for user in var.test_users : user.username => user }

  triggers = {
    username = each.value.username
  }
}

resource "random_string" "subject_id" {
  for_each = { for user in var.test_users : user.username => user }

  keepers = {
    username = each.value.username
  }

  lower   = true
  upper   = true
  special = false
  number  = true
  length  = 32
}

resource "random_string" "public_subject_id" {
  for_each = { for user in var.test_users : user.username => user }

  keepers = {
    username = each.value.username
  }

  lower   = true
  upper   = true
  special = false
  number  = true
  length  = 32
}

resource "aws_dynamodb_table_item" "user_credentials" {
  for_each = { for user in var.test_users : user.username => user }

  table_name = data.aws_dynamodb_table.user_credential_table.name
  hash_key   = data.aws_dynamodb_table.user_credential_table.hash_key
  item = jsonencode({
    "Email" = {
      "S" = each.value.username
    },
    "Updated" = {
      "S" = formatdate("YYYY-MM-DD'T'hh:mm:ss.000000", time_static.create_date[each.key].rfc3339)
    },
    "SubjectID" = {
      "S" = random_string.subject_id[each.key].result
    },
    "Password" = {
      "S" = each.value.hashed_password
    },
    "Created" = {
      "S" = formatdate("YYYY-MM-DD'T'hh:mm:ss.000000", time_static.create_date[each.key].rfc3339)
    }
  })
}

resource "aws_dynamodb_table_item" "user_profile" {
  for_each = { for user in var.test_users : user.username => user }

  table_name = data.aws_dynamodb_table.user_profile_table.name
  hash_key   = data.aws_dynamodb_table.user_profile_table.hash_key
  item = jsonencode({
    "Email" = {
      "S" = each.value.username
    },
    "EmailVerified" = {
      "N" = "1"
    },
    "PhoneNumberVerified" = {
      "N" = "1"
    },
    "SubjectID" = {
      "S" = random_string.subject_id[each.key].result
    },
    "PhoneNumber" = {
      "S" = each.value.phone
    },
    "PublicSubjectID" = {
      "S" = random_string.public_subject_id[each.key].result
    },
    "termsAndConditions" = {
      "M" = {
        "version" = {
          "S" = "1.0"
        },
        "timestamp" = {
          "S" = formatdate("YYYY-MM-DD'T'hh:mm:ss.000000", time_static.create_date[each.key].rfc3339)
        }
      }
    },
    "Updated" = {
      "S" = formatdate("YYYY-MM-DD'T'hh:mm:ss.000000", time_static.create_date[each.key].rfc3339)
    },
    "Created" = {
      "S" = formatdate("YYYY-MM-DD'T'hh:mm:ss.000000", time_static.create_date[each.key].rfc3339)
    }
  })
}