locals {
  prod           = var.environment == "production" ? "account.gov.uk" : ""
  sandpitdevs    = var.environment == "authdev1" || var.environment == "authdev2" ? "${var.environment}.sandpit.account.gov.uk" : ""
  newdevs        = var.environment == "authdev3" ? "${var.environment}.dev.account.gov.uk" : ""
  otherenv       = var.environment != "production" && var.environment != "authdev1" && var.environment != "authdev2" && var.environment != "authdev3" ? "${var.environment}.account.gov.uk" : ""
  service_domain = coalesce(local.prod, local.sandpitdevs, local.otherenv, local.newdevs)

  account_management_api_fqdn = "manage.${local.service_domain}"
  frontend_fqdn               = "signin.${local.service_domain}"
  oidc_api_fqdn               = "oidc.${local.service_domain}"
}

# TODO: delete
data "aws_route53_zone" "service_domain" {
  name = local.service_domain
}

resource "aws_route53_zone" "account_management_api_zone" {
  name = local.account_management_api_fqdn

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_acm_certificate" "account_management_api" {
  domain_name       = local.account_management_api_fqdn
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "account_management_api_certificate_validation" {
  for_each = {
    for dvo in aws_acm_certificate.account_management_api.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = aws_route53_zone.account_management_api_zone.zone_id
}

# TODO: delete
resource "aws_route53_record" "account_management_api_certificate_validation_live" {
  for_each = {
    for dvo in aws_acm_certificate.account_management_api.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.service_domain.zone_id
}

resource "aws_acm_certificate_validation" "account_management_api" {
  certificate_arn         = aws_acm_certificate.account_management_api.arn
  validation_record_fqdns = [for record in aws_route53_record.account_management_api_certificate_validation : record.fqdn]

}

resource "aws_api_gateway_domain_name" "account_management_api" {
  regional_certificate_arn = aws_acm_certificate_validation.account_management_api.certificate_arn
  domain_name              = local.account_management_api_fqdn

  security_policy = "TLS_1_2"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_route53_record" "account_management_api" {
  name    = local.account_management_api_fqdn
  type    = "A"
  zone_id = aws_route53_zone.account_management_api_zone.zone_id

  alias {
    evaluate_target_health = true
    name                   = aws_api_gateway_domain_name.account_management_api.regional_domain_name
    zone_id                = aws_api_gateway_domain_name.account_management_api.regional_zone_id
  }
}

output "account_management_api_name_servers" {
  value = aws_route53_zone.account_management_api_zone.name_servers
}
