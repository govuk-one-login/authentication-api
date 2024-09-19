data "aws_iam_policy" "redis_parameter_policy" {
  arn = local.redis_ssm_parameter_policy
}

resource "aws_iam_policy" "redis_parameter_policy" {
  policy      = data.aws_iam_policy.redis_parameter_policy.policy
  path        = "/${var.environment}/redis/${local.redis_key}/"
  name_prefix = "parameter-store-policy"
}
