output "base_url" {
  value = local.api_base_url
}

output "api_gateway_root_id" {
  value = aws_api_gateway_rest_api.di_authentication_api.id
}

output "stub_rp_client_credentials" {
  value = [for i, rp in var.stub_rp_clients : {
    client_name = rp.client_name
    client_id = random_string.stub_rp_client_id[i].result
    private_key = tls_private_key.stub_rp_client_private_key[i].private_key_pem
    public_key = tls_private_key.stub_rp_client_private_key[i].public_key_pem
  }]
  sensitive = true
}