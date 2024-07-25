data "aws_iam_account_alias" "current" {
  count = var.account_alias == null ? 0 : 1
}

locals {
  account_alias = var.account_alias == null ? data.aws_iam_account_alias.current[0].account_alias : var.account_alias
}
