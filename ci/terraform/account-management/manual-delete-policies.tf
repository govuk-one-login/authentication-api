
data "aws_iam_policy_document" "permit_send_email_queue_policy_document" {
  statement {
    sid    = "SendSQS"
    effect = "Allow"


    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
    ]

    resources = [
      aws_sqs_queue.email_queue.arn
    ]
  }
}

resource "aws_iam_policy" "permit_send_email_queue_policy" {
  name_prefix = "permit-send-email-queue-policy"
  path        = "/${var.environment}/am/"
  description = "IAM policy to allow sending messages to the account management email queue"

  policy = data.aws_iam_policy_document.permit_send_email_queue_policy_document.json
}

data "aws_iam_policy_document" "legacy_account_deletion_topic" {
  statement {
    sid    = "SendAccountDeletionSNS"
    effect = "Allow"

    actions = [
      "sns:Publish"
    ]

    resources = [
      local.account_deletion_topic_arn
    ]
  }
}

data "aws_iam_policy_document" "legacy_account_deletion_key" {
  statement {
    sid    = "KMSAccessForAccountDeletionSNS"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt"
    ]
    resources = [var.legacy_account_deletion_topic_key_arn]
  }
}

data "aws_iam_policy_document" "legacy_account_deletion_access" {
  source_policy_documents = var.legacy_account_deletion_topic_key_arn == "" ? [data.aws_iam_policy_document.legacy_account_deletion_topic.json] : [data.aws_iam_policy_document.legacy_account_deletion_topic.json, data.aws_iam_policy_document.legacy_account_deletion_key.json]
}

resource "aws_iam_policy" "legacy_account_deletion_topic" {
  name_prefix = "permit-send-legacy-account-deletion-topic"
  path        = "/${var.environment}/am/"
  description = "Allow the manual account deletion lambda to post to the SNS topic owned by Home"
  policy      = data.aws_iam_policy_document.legacy_account_deletion_access.json
}

resource "aws_sns_topic" "mock_account_deletion_topic" {
  count = var.legacy_account_deletion_topic_arn == null ? 1 : 0
  name  = "${var.environment}-mock-account-deletion-topic"
}
