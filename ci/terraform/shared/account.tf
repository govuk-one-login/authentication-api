data "aws_iam_account_alias" "current" {}
output "aws_account_alias" {
  description = "The alias of the current AWS account"
  value       = data.aws_iam_account_alias.current.account_alias
}
