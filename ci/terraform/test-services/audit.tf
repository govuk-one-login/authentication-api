module "test_services_txma_audit" {
  source          = "../modules/txma-audit-queue"
  environment     = var.environment
  txma_account_id = var.txma_account_id
  service_name    = "test-services"
}
