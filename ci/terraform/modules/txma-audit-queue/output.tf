output "queue_arn" {
  value = aws_sqs_queue.txma_audit_queue.arn
}

output "queue_url" {
  value = aws_sqs_queue.txma_audit_queue.url
}

output "kms_key_arn" {
  value = var.use_localstack ? aws_kms_key.txma_audit_queue_encryption_key[0].arn : null
}