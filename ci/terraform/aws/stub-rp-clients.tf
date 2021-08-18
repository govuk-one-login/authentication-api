resource "tls_private_key" "stub_rp_client_private_key" {
  count = length(var.stub_rp_clients)

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "random_string" "stub_rp_client_id" {
  count = length(var.stub_rp_clients)

  lower   = true
  upper   = true
  special = false
  number  = true
  length  = 32
}


resource "aws_dynamodb_table_item" "stub_rp_client" {
  count = length(var.stub_rp_clients)

  table_name = aws_dynamodb_table.client_registry_table.name
  hash_key   = aws_dynamodb_table.client_registry_table.hash_key

  item = jsonencode({
    ClientID = {
      S = random_string.stub_rp_client_id[count.index].result
    }
    ClientName = {
      S = var.stub_rp_clients[count.index].client_name
    }
    Contacts = {
      L = [{
        S = "contact+${var.stub_rp_clients[count.index].client_name}@example.com"
      }]
    }
    PostLogoutRedirectUrls = {
      L = [for url in var.stub_rp_clients[count.index].logout_urls : {
        S = url
      }]
    }
    RedirectUrls = {
      L = [for url in var.stub_rp_clients[count.index].callback_urls : {
        S = url
      }]
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
      S = replace(replace(
        replace(
        tls_private_key.stub_rp_client_private_key[count.index].public_key_pem, "-----BEGIN PUBLIC KEY-----", ""),
      "-----END PUBLIC KEY-----", ""), "\n", "")
    }
  })
}