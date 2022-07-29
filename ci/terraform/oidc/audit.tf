module "oidc_txma_audit" {
  count           = contains(["build", "staging"], var.environment) ? 1 : 0
  source          = "../modules/txma-audit-queue"
  environment     = var.environment
  txma_account_id = var.txma_account_id
  use_localstack  = false
}