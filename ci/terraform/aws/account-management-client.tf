resource "random_string" "account_management_client_id" {
  lower   = true
  upper   = true
  special = false
  number  = true
  length = 32
}

data "aws_kms_public_key" "account_management_jwt_key" {
  depends_on = [aws_kms_key.account_management_jwt_key]
  key_id = aws_kms_key.account_management_jwt_key.arn
}

resource "aws_dynamodb_table_item" "account_management_client" {
  table_name = aws_dynamodb_table.client_registry_table.name
  hash_key   = aws_dynamodb_table.client_registry_table.hash_key

  item     = jsonencode({
    ClientID = {
      S = random_string.account_management_client_id.result
    }
    ClientName = {
      S = "${var.environment}-account-managment"
    }
    Contacts = {
      L = []
    }
    PostLogoutRedirectUrls = {
      L = []
    }
    RedirectUrls = {
      L = [
        {
          S = "https://account-management.${var.environment}.${var.service_domain_name}/auth/callback"
        }
      ]
    }
    Scopes = {
      L = [
        {
          S = "openid"
        },
        {
          S = "phone"
        },
        {
          S = "email"
        },
      ]
    }
    PublicKey = {
      S = "paste me manually until Terraform provider bug is fixed"
    }
  })
}
