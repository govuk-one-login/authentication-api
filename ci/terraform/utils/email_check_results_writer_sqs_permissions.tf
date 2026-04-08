### Permissions for Lambda to access SQS (including decrpyting messages)
resource "aws_iam_policy" "email_check_queue_policy" {
  depends_on = [
    data.aws_iam_policy_document.email_check_result_queue_policy_document,
  ]

  name   = "${var.environment}-email-check-queue"
  policy = data.aws_iam_policy_document.email_check_result_queue_policy_document.json
}

data "aws_iam_policy_document" "email_check_result_queue_policy_document" {
  statement {
    sid    = "ReceiveSQS"
    effect = "Allow"

    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ChangeMessageVisibility",
    ]

    resources = [
      var.email_check_results_sqs_queue_arn
    ]
  }
}

data "aws_iam_policy_document" "email_check_sqs_kms_decrypt_policy_document" {
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.email_check_results_sqs_queue_encryption_key_arn]
  }
}

resource "aws_iam_policy" "email_check_sqs_kms_decrypt_policy" {
  name        = "${var.environment}-email-check-sqs-kms-decrypt"
  description = "Policy for email check writer to decrypt email check results SQS messages (which are server-side encrypted with a customer managed key)"
  policy      = data.aws_iam_policy_document.email_check_sqs_kms_decrypt_policy_document.json
}

### Permissions for SQS to trigger Lambda
resource "aws_lambda_permission" "allow_sqs_invoke" {
  statement_id  = "SQSInvokeFunction"
  action        = "lambda:InvokeFunction"
  function_name = module.email_check_results_writer_lambda.endpoint_lambda_function.function_name

  principal  = "sqs.amazonaws.com"
  source_arn = var.email_check_results_sqs_queue_arn
}
