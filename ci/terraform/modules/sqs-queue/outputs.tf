output "queue_arn" {
  value = aws_sqs_queue.queue.arn
}

output "queue_name" {
  value = aws_sqs_queue.queue.name
}