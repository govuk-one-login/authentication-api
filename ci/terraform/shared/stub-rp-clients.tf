resource "tls_private_key" "stub_relying_party_client_private_key" {
  for_each = { for client in var.stub_rp_clients : client.client_name => client }

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "random_string" "stub_relying_party_client_id" {
  for_each = { for client in var.stub_rp_clients : client.client_name => client }

  lower   = true
  upper   = true
  special = false
  numeric = true
  length  = 32
}

locals {
  acceptance_test_rp_client_emails = {
    pattern = "test-user+${var.environment}-$${instantiationMillis}-$${counter}@test.null.local" # '$${' = literal '${' (escaped)
    regex   = "^test-user\\+${var.environment}-\\d+-\\d+@test\\.null\\.local$"
  }
  orch_acceptance_test_rp_client_emails = {
    regex = "^orch-test-user\\d*@digital.cabinet-office.gov.uk$"
  }
}

resource "aws_dynamodb_table_item" "stub_relying_party_client" {
  for_each = { for client in var.stub_rp_clients : client.client_name => client }

  table_name = aws_dynamodb_table.client_registry_table.name
  hash_key   = aws_dynamodb_table.client_registry_table.hash_key

  item = jsonencode(
    merge(
      {
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
        }
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
        IdentityVerificationSupported = {
          N = "1"
        }
        ClientType = {
          S = each.value.client_type
        }
        TestClient = {
          N = each.value.test_client
        }
        TestClientEmailAllowlist = {
          L = [for email in concat(split(",", var.test_client_email_allowlist), [local.acceptance_test_rp_client_emails.regex], [local.orch_acceptance_test_rp_client_emails.regex]) : {
            S = email
          }]
        }
        OneLoginService = {
          BOOL = each.value.one_login_service
        }
        ClientLoCs = {
          L = [
            {
              S = "P0"
            },
            {
              S = "P1"
            },
            {
              S = "P2"
            },
            {
              S = "P3"
            }
          ]
        }
        MaxAgeEnabled = {
          BOOL = each.value.max_age_enabled
        }
      }, each.value.back_channel_logout_uri != null ?
      {
        BackChannelLogoutUri = {
          S = each.value.back_channel_logout_uri
        }
      } : {}
    )
  )
}
