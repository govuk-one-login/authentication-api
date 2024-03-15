resource "tls_private_key" "stub_rp_client_private_key" {
  count = length(var.stub_rp_clients)

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_private_key" "stub_relying_party_client_private_key" {
  for_each = { for client in var.stub_rp_clients : client.client_name => client }

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "random_string" "stub_rp_client_id" {
  count = length(var.stub_rp_clients)

  lower   = true
  upper   = true
  special = false
  numeric = true
  length  = 32
}

resource "random_string" "stub_relying_party_client_id" {
  for_each = { for client in var.stub_rp_clients : client.client_name => client }

  lower   = true
  upper   = true
  special = false
  numeric = true
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
    SectorIdentifierUri = {
      S = var.stub_rp_clients[count.index].sector_identifier_uri
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
      L = [for scope in var.stub_rp_clients[count.index].scopes : {
        S = scope
      }]
    },
    Claims = {
      L = [
        {
          S = "https://vocab.account.gov.uk/v1/coreIdentityJWT"
        },
        {
          S = "https://vocab.account.gov.uk/v1/passport"
        },
        {
          S = "https://vocab.account.gov.uk/v1/address"
        },
        {
          S = "https://vocab.account.gov.uk/v1/drivingPermit"
        },
        {
          S = "https://vocab.account.gov.uk/v1/socialSecurityRecord"
        },
        {
          S = "https://vocab.account.gov.uk/v1/returnCode"
        },
        {
          S = "https://vocab.account.gov.uk/v1/inheritedIdentityJWT"
        },
      ]
    }
    PublicKey = {
      S = replace(replace(
        replace(
        tls_private_key.stub_rp_client_private_key[count.index].public_key_pem, "-----BEGIN PUBLIC KEY-----", ""),
      "-----END PUBLIC KEY-----", ""), "\n", "")
    }
    ServiceType = {
      S = var.stub_rp_clients[count.index].service_type
    }
    SubjectType = {
      S = "pairwise"
    }
    CookieConsentShared = {
      N = "1"
    }
    ConsentRequired = {
      N = var.stub_rp_clients[count.index].consent_required
    }
    IdentityVerificationSupported = {
      N = var.stub_rp_clients[count.index].identity_verification_supported
    }
    ClientType = {
      S = var.stub_rp_clients[count.index].client_type
    }
    TestClient = {
      N = var.stub_rp_clients[count.index].test_client
    }
    TestClientEmailAllowlist = {
      L = [for email in split(",", var.test_client_email_allowlist) : {
        S = email
      }]
    }
    OneLoginService = {
      BOOL = var.stub_rp_clients[count.index].one_login_service
    }
  })
}

resource "aws_dynamodb_table_item" "stub_relying_party_client" {
  for_each = { for client in var.stub_rp_clients : client.client_name => client }

  table_name = aws_dynamodb_table.client_registry_table.name
  hash_key   = aws_dynamodb_table.client_registry_table.hash_key

  item = jsonencode({
    ClientID = {
      S = random_string.stub_relying_party_client_id[each.value.client_name].result
    }
    ClientName = {
      S = each.value.client_name
    }
    Contacts = {
      L = [{
        S = "contact+${each.value.client_name}@example.com"
      }]
    }
    SectorIdentifierUri = {
      S = each.value.sector_identifier_uri
    }
    PostLogoutRedirectUrls = {
      L = [for url in each.value.logout_urls : {
        S = url
      }]
    }
    RedirectUrls = {
      L = [for url in each.value.callback_urls : {
        S = url
      }]
    }
    Scopes = {
      L = [for scope in each.value.scopes : {
        S = scope
      }]
    },
    Claims = {
      L = [
        {
          S = "https://vocab.account.gov.uk/v1/coreIdentityJWT"
        },
        {
          S = "https://vocab.account.gov.uk/v1/passport"
        },
        {
          S = "https://vocab.account.gov.uk/v1/address"
        },
        {
          S = "https://vocab.account.gov.uk/v1/drivingPermit"
        },
        {
          S = "https://vocab.account.gov.uk/v1/socialSecurityRecord"
        },
        {
          S = "https://vocab.account.gov.uk/v1/returnCode"
        },
        {
          S = "https://vocab.account.gov.uk/v1/inheritedIdentityJWT"
        },
      ]
    }
    PublicKey = {
      S = replace(replace(
        replace(
        tls_private_key.stub_relying_party_client_private_key[each.value.client_name].public_key_pem, "-----BEGIN PUBLIC KEY-----", ""),
      "-----END PUBLIC KEY-----", ""), "\n", "")
    }
    ServiceType = {
      S = each.value.service_type
    }
    SubjectType = {
      S = "pairwise"
    }
    CookieConsentShared = {
      N = "1"
    }
    ConsentRequired = {
      N = each.value.consent_required
    }
    IdentityVerificationSupported = {
      N = each.value.identity_verification_supported
    }
    ClientType = {
      S = each.value.client_type
    }
    TestClient = {
      N = each.value.test_client
    }
    TestClientEmailAllowlist = {
      L = [for email in split(",", var.test_client_email_allowlist) : {
        S = email
      }]
    }
    OneLoginService = {
      BOOL = each.value.one_login_service
    }
  })
}
