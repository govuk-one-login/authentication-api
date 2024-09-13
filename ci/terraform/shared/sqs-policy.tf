data "aws_iam_policy_document" "pending_email_check_queue_subscription_policy_document" {
  statement {
    effect = "Allow"

    sid = "AllowReadDeleteAccessToPendingEmailCheckQueue"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.auth_check_account_id}:root"]
    }
    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
    ]
    resources = [
      aws_sqs_queue.pending_email_check_queue.arn,
    ]
  }
}

resource "aws_sqs_queue_policy" "pending_email_check_queue_subscription" {
  queue_url = aws_sqs_queue.pending_email_check_queue.id

  policy = data.aws_iam_policy_document.pending_email_check_queue_subscription_policy_document.json
}


# Experian phone check Sqs IAM roles and permissions (resorce moved from contra Repo)

module "experian_phone_check_sqs_lambda_role" {
  source      = "github.com/govuk-one-login/authentication-api/ci/terraform/modules/lambda-role"
  environment = var.environment
  role_name   = "experian_phone_check_sqs_lambda_role"
  vpc_arn     = local.vpc_arn

  policies_to_attach = [
    aws_iam_policy.experian_phone_check_sqs_queue_send_access_policy.arn,
    aws_iam_policy.experian_phone_check_sqs_dl_queue_send_access_policy.arn,
    aws_iam_policy.parameter_policy_phone_check.arn,
    aws_iam_policy.txma_audit_queue_access_policy.arn
  ]

}

data "aws_iam_policy_document" "experian_phone_check_sqs_queue_send_access_policy_document" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-experian-phone-check-queue-send-access-policy"

  statement {
    effect = "Allow"
    sid    = "AllowWriteAccessToExperianPhoneCheckQueue"
    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
    ]
    resources = [aws_sqs_queue.experian_phone_check_sqs_queue.arn]
  }

  statement {
    effect = "Allow"
    sid    = "AllowLambdasToEncryptWithCustomKey"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      aws_kms_key.experian_phone_check_sqs_queue_encryption_key.arn
    ]
  }
}

data "aws_iam_policy_document" "experian_phone_check_dl_sqs_queue_send_access_policy_document" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-experian-phone-check-dl-queue-send-access-policy"

  statement {
    effect = "Allow"
    sid    = "AllowWriteAccessToExperianPhoneCheckQueue"
    actions = [
      "sqs:SendMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueAttributes",
    ]
    resources = [aws_sqs_queue.experian_phone_check_sqs_dead_letter_queue.arn]
  }

  statement {
    effect = "Allow"
    sid    = "AllowLambdasToEncryptWithCustomKey"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      aws_kms_key.experian_phone_check_sqs_dl_queue_encryption_key.arn
    ]
  }
}

data "aws_iam_policy_document" "experian_phone_check_sqs_queue_and_dl_receive_access_policy_document" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-experian-phone-check-queue-receive-access-policy"

  statement {
    effect = "Allow"
    sid    = "AllowReceiveAccessToExperianPhoneCheckQueue"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ChangeMessageVisibility"
    ]
    resources = [
      aws_sqs_queue.experian_phone_check_sqs_queue.arn
    ]
  }
  statement {
    effect = "Allow"
    sid    = "AllowReceiveAccessToExperianDLPhoneCheckQueue"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ChangeMessageVisibility"
    ]
    resources = [
      aws_sqs_queue.experian_phone_check_sqs_dead_letter_queue.arn
    ]
  }
  statement {
    effect = "Allow"
    sid    = "AllowLambdasToEncryptWithCustomKey"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      aws_kms_key.experian_phone_check_sqs_queue_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "experian_phone_check_sqs_queue_and_dl_receive_access_policy" {
  name_prefix = "experian-phone-check-queue-receive-access-"
  path        = "/${var.environment}/"
  description = "IAM Policy for receive access to the experian phone check queue"

  policy = data.aws_iam_policy_document.experian_phone_check_sqs_queue_and_dl_receive_access_policy_document.json
}

resource "aws_iam_policy" "experian_phone_check_sqs_queue_send_access_policy" {
  name_prefix = "experian-phone-check-queue-send-access-"
  path        = "/${var.environment}/"
  description = "IAM Policy for send access to the experian phone check queue"

  policy = data.aws_iam_policy_document.experian_phone_check_sqs_queue_send_access_policy_document.json
}

resource "aws_iam_policy" "experian_phone_check_sqs_dl_queue_send_access_policy" {
  name_prefix = "experian-phone-check-dl-queue-send-access-"
  path        = "/${var.environment}/"
  description = "IAM Policy for send access to the experian phone check queue"

  policy = data.aws_iam_policy_document.experian_phone_check_dl_sqs_queue_send_access_policy_document.json
}

data "aws_iam_policy_document" "experian_phone_check_sqs_queue_policy_document" {
  statement {
    sid    = "SendAndReceiveExperianDL"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [module.experian_phone_check_sqs_lambda_role.arn]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ReceiveMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [aws_sqs_queue.experian_phone_check_sqs_queue.arn]
  }

  depends_on = [aws_sqs_queue.experian_phone_check_sqs_queue]
}

data "aws_iam_policy_document" "experian_phone_check_sqs_dl_queue_policy_document" {
  statement {
    sid    = "SendAndReceiveExperianDL"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [module.experian_phone_check_sqs_lambda_role.arn]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ReceiveMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]

    resources = [aws_sqs_queue.experian_phone_check_sqs_dead_letter_queue.arn]
  }

  depends_on = [aws_sqs_queue.experian_phone_check_sqs_dead_letter_queue]
}

resource "aws_sqs_queue_policy" "experian_phone_check_sqs_dl_queue_policy" {
  depends_on = [
    data.aws_iam_policy_document.experian_phone_check_sqs_dl_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.experian_phone_check_sqs_dead_letter_queue.id
  policy    = data.aws_iam_policy_document.experian_phone_check_sqs_dl_queue_policy_document.json
}

resource "aws_sqs_queue_policy" "experian_phone_check_sqs_queue_policy" {
  depends_on = [
    data.aws_iam_policy_document.experian_phone_check_sqs_queue_policy_document,
  ]

  queue_url = aws_sqs_queue.experian_phone_check_sqs_queue.id
  policy    = data.aws_iam_policy_document.experian_phone_check_sqs_queue_policy_document.json
}

data "aws_iam_policy_document" "txma_audit_queue_access_policy_document" {
  version   = "2012-10-17"
  policy_id = "${var.environment}-txma-audit-queue-access-policy"

  statement {
    effect    = "Allow"
    sid       = "AllowWriteAccessToTxmaAuditQueue"
    actions   = ["sqs:SendMessage", ]
    resources = [data.aws_sqs_queue.txma_audit_queue.arn]
  }

  statement {
    effect = "Allow"
    sid    = "AllowAccessToKeyForEncryptingPayloads"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      data.aws_kms_key.txma_audit_queue_encryption_key.arn
    ]
  }
}

resource "aws_iam_policy" "txma_audit_queue_access_policy" {
  name_prefix = "txma-audit-queue-access-"
  path        = "/${var.environment}/"
  description = "IAM Policy for write access to the TxMA audit queue"

  policy = data.aws_iam_policy_document.txma_audit_queue_access_policy_document.json
}
