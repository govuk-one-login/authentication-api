output "queue_arn" {
  value = aws_sqs_queue.txma_audit_queue.arn
}

output "queue_url" {
  value = aws_sqs_queue.txma_audit_queue.url
}

output "kms_key_arn" {
  value = aws_kms_key.txma_audit_queue_encryption_key.arn
}

output "access_policy_arn" {
  value = aws_iam_policy.txma_audit_queue_access_policy.arn
}