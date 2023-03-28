
data "aws_dynamodb_table" "account_recovery_block_table" {
  name = "${var.environment}-account-recovery-block"
}

resource "aws_dynamodb_table_item" "account-recovery-block" {
  for_each = { for block in var.test_account_recovery_blocks : block.username => block }

  table_name = data.aws_dynamodb_table.account_recovery_block_table.name
  hash_key   = data.aws_dynamodb_table.account_recovery_block_table.hash_key
  item = jsonencode({
    "Email" = {
      "S" = each.value.username
    },
    "TimeToExist" = {
      "N" = each.value.time_to_exist
    }
  })
}