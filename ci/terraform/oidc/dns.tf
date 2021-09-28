/*
data "terraform_remote_state" "dns" {
  count   = var.use_localstack ? 0 : 1
  backend = "s3"
  config = {
    bucket   = var.dns_state_bucket
    key      = var.dns_state_key
    role_arn = var.dns_state_role
    region   = var.aws_region
  }
}
*/
locals {
  //frontend_base_url = var.use_localstack ? var.frontend_base_url : lookup(data.terraform_remote_state.dns[0].outputs, "${var.environment}_frontend_url", "")
  frontend_base_url =  var.frontend_base_url 
}