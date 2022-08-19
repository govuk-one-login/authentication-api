module "acct_mgmt_txma_audit" {
  source          = "../modules/txma-audit-queue"
  environment     = var.environment
  txma_account_id = var.txma_account_id
  service_name    = "acct-mgmt"
}

module "account_management_txma_audit" {
  source          = "../modules/txma-audit-queue"
  environment     = var.environment
  txma_account_id = var.txma_account_id
  service_name    = "account-mgmt"
}