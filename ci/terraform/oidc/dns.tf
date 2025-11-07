locals {
  prod           = var.environment == "production" ? "account.gov.uk" : ""
  newdevs        = var.environment == "authdev3" || var.environment == "authdev1" || var.environment == "authdev2" ? "${var.environment}.dev.account.gov.uk" : ""
  otherenv       = var.environment != "production" && var.environment != "authdev1" && var.environment != "authdev2" && var.environment != "authdev3" ? "${var.environment}.account.gov.uk" : ""
  service_domain = coalesce(local.prod, local.otherenv, local.newdevs)

  oidc_cloudfront_id_export_name = var.environment == "sandpit" || var.environment == "authdev3" ? "dev-oidc-cloudfront-DistributionId" : "${var.environment}-oidc-cloudfront-DistributionId"

  account_management_fqdn = local.service_domain
  frontend_fqdn           = "signin.${local.service_domain}"
  frontend_api_fqdn       = "auth.${local.service_domain}"
  oidc_api_fqdn           = "oidc.${local.service_domain}"
  oidc_origin_api_fqdn    = "origin.${local.oidc_api_fqdn}"
}

# TODO: delete
data "aws_route53_zone" "service_domain" {
  name = local.service_domain
}

resource "aws_route53_zone" "oidc_api_zone" {
  name = local.oidc_api_fqdn

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_acm_certificate" "oidc_api" {
  domain_name       = local.oidc_api_fqdn
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "oidc_api_certificate_validation" {
  for_each = {
    for dvo in aws_acm_certificate.oidc_api.domain_validation_options : dvo.domain_name => {
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
  zone_id         = aws_route53_zone.oidc_api_zone.zone_id
}

# TODO: delete
resource "aws_route53_record" "oidc_api_certificate_validation_live" {
  for_each = {
    for dvo in aws_acm_certificate.oidc_api.domain_validation_options : dvo.domain_name => {
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

resource "aws_acm_certificate_validation" "oidc_api" {
  certificate_arn         = aws_acm_certificate.oidc_api.arn
  validation_record_fqdns = [for record in aws_route53_record.oidc_api_certificate_validation : record.fqdn]

}

resource "aws_api_gateway_domain_name" "oidc_api" {
  regional_certificate_arn = aws_acm_certificate_validation.oidc_api.certificate_arn
  domain_name              = local.oidc_api_fqdn

  security_policy = "TLS_1_2"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

data "aws_cloudformation_export" "oidc_cloudfront_distribution_id" {
  count = var.oidc_cloudfront_enabled ? 1 : 0
  name  = local.oidc_cloudfront_id_export_name
}

data "aws_cloudfront_distribution" "oidc_cloudfront_distribution" {
  count = var.oidc_cloudfront_enabled ? 1 : 0
  id    = data.aws_cloudformation_export.oidc_cloudfront_distribution_id[0].value
}

resource "aws_route53_record" "oidc_api" {
  name    = local.oidc_api_fqdn
  type    = "A"
  zone_id = aws_route53_zone.oidc_api_zone.zone_id

  alias {
    evaluate_target_health = true
    name                   = var.oidc_cloudfront_enabled ? data.aws_cloudfront_distribution.oidc_cloudfront_distribution[0].domain_name : aws_api_gateway_domain_name.oidc_api.regional_domain_name
    zone_id                = var.oidc_cloudfront_enabled ? data.aws_cloudfront_distribution.oidc_cloudfront_distribution[0].hosted_zone_id : aws_api_gateway_domain_name.oidc_api.regional_zone_id
  }
}

output "oidc_api_name_servers" {
  value = aws_route53_zone.oidc_api_zone.name_servers
}

resource "aws_route53_record" "oidc_origin_api" {
  count   = var.oidc_cloudfront_enabled ? 1 : 0
  name    = local.oidc_origin_api_fqdn
  type    = "A"
  zone_id = aws_route53_zone.oidc_api_zone.zone_id

  alias {
    evaluate_target_health = true
    name                   = aws_api_gateway_domain_name.oidc_api.regional_domain_name
    zone_id                = aws_api_gateway_domain_name.oidc_api.regional_zone_id
  }
}

resource "aws_route53_zone" "frontend_api_zone" {
  name = local.frontend_api_fqdn

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_acm_certificate" "frontend_api" {
  domain_name       = local.frontend_api_fqdn
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "frontend_api_certificate_validation" {
  for_each = {
    for dvo in aws_acm_certificate.frontend_api.domain_validation_options : dvo.domain_name => {
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
  zone_id         = aws_route53_zone.frontend_api_zone.zone_id
}

# TODO: delete
resource "aws_route53_record" "frontend_api_certificate_validation_live" {
  for_each = {
    for dvo in aws_acm_certificate.frontend_api.domain_validation_options : dvo.domain_name => {
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

resource "aws_acm_certificate_validation" "frontend_api" {
  certificate_arn         = aws_acm_certificate.frontend_api.arn
  validation_record_fqdns = [for record in aws_route53_record.frontend_api_certificate_validation : record.fqdn]
}

resource "aws_api_gateway_domain_name" "frontend_api" {
  regional_certificate_arn = aws_acm_certificate_validation.frontend_api.certificate_arn
  domain_name              = local.frontend_api_fqdn

  security_policy = "TLS_1_2"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_route53_record" "frontend_api" {
  name    = local.frontend_api_fqdn
  type    = "A"
  zone_id = aws_route53_zone.frontend_api_zone.zone_id

  alias {
    evaluate_target_health = true
    name                   = aws_api_gateway_domain_name.frontend_api.regional_domain_name
    zone_id                = aws_api_gateway_domain_name.frontend_api.regional_zone_id
  }
}

output "frontend_api_name_servers" {
  value = aws_route53_zone.frontend_api_zone.name_servers
}
