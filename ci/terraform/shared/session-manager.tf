locals {
  session_manager_resource_count = module.primary_environment.is_primary_environment ? 1 : 0
}
data "aws_iam_policy_document" "ssm_kms_access" {
  count = local.session_manager_resource_count

  statement {
    sid = "KMSPolicyAllowIAMManageAccess"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = [
      "kms:Update*",
      "kms:UntagResource",
      "kms:TagResource",
      "kms:ScheduleKeyDeletion",
      "kms:Revoke*",
      "kms:Put*",
      "kms:List*",
      "kms:Get*",
      "kms:Enable*",
      "kms:Disable*",
      "kms:Describe*",
      "kms:Delete*",
      "kms:Create*",
      "kms:CancelKeyDeletion"
    ]
    resources = ["*"]
  }

  statement {
    sid = "AllowSSMUseOfKey"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = [
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Encrypt",
      "kms:DescribeKey",
      "kms:Decrypt"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["ssm.${var.aws_region}.amazonaws.com"]
    }
  }
  # Enabling this means people can start interactive sessions. Port forwarding works without this!
  # statement {
  #   sid = "AllowSSOUsersToUseKey"
  #   principals {
  #     type = "AWS"
  #     identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
  #   }
  #   actions = [
  #     "kms:Decrypt",
  #     "kms:Encrypt",
  #     "kms:GenerateDataKey*",
  #     "kms:ReEncrypt*"
  #   ]
  #   resources = ["*"]
  # }

  statement {
    sid = "AllowCloudWatchLogsKMSWithContext"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    actions = [
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Encrypt",
      "kms:Decrypt"
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }

  statement {
    sid = "AllowCloudWatchLogsKMSDescribeKey"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    actions = [
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }
}

resource "aws_kms_key" "ssm_access_key" {
  count = local.session_manager_resource_count

  description             = "Key used to grant access for session-manager logs"
  policy                  = data.aws_iam_policy_document.ssm_kms_access[count.index].json
  enable_key_rotation     = true
  deletion_window_in_days = 30
}


resource "aws_kms_alias" "ssm_key_alias" {
  count = local.session_manager_resource_count

  name          = "alias/kms/${var.aws_region}-session-manager-logs-key"
  target_key_id = aws_kms_key.ssm_access_key[count.index].id
}

## Create the CloudWatch log group for session logs ##

resource "aws_cloudwatch_log_group" "ssm_logs" {
  count = local.session_manager_resource_count

  name_prefix       = "${var.aws_region}-session-manager-log-group-"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.ssm_access_key[count.index].arn
}

## Create a policy to allow EC2 instances to access KMS + Cloudwatch ##

data "aws_iam_policy_document" "session_manager_ec2_policy" {
  count = local.session_manager_resource_count

  statement {
    sid    = "AllowKMSAccess"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
    ]

    resources = [
      aws_kms_key.ssm_access_key[count.index].arn,
    ]
  }

  statement {
    sid    = "AllowCloudwatchAccess"
    effect = "Allow"

    actions = [
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
      "logs:CreateLogStream",
    ]

    resources = [
      aws_cloudwatch_log_group.ssm_logs[count.index].arn,
      "${aws_cloudwatch_log_group.ssm_logs[count.index].arn}:*"
    ]
  }

  statement {
    sid    = "AllowCloudwatch"
    effect = "Allow"

    actions = [
      "logs:DescribeLogGroups"
    ]

    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group::log-stream:"
    ]
  }
}

resource "aws_iam_policy" "session_manager_ec2_policy" {
  count = local.session_manager_resource_count

  name   = "${var.aws_region}-session-manager-ec2-policy"
  policy = data.aws_iam_policy_document.session_manager_ec2_policy[count.index].json
}

## Create the RunShell document for SSM ##

resource "aws_ssm_document" "session_manager_prefs" {
  count = local.session_manager_resource_count

  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = <<DOC
{
    "schemaVersion": "1.0",
    "description": "SSM document to house preferences for session manager",
    "sessionType": "Standard_Stream",
    "inputs": {
        "cloudWatchLogGroupName": "${aws_cloudwatch_log_group.ssm_logs[count.index].name}",
        "cloudWatchEncryptionEnabled": true,
        "runAsEnabled": false,
        "kmsKeyId": "${aws_kms_alias.ssm_key_alias[count.index].arn}",
        "cloudWatchStreamingEnabled": true,
        "idleSessionTimeout": "20"
    }
}
DOC

  depends_on = [
    aws_cloudwatch_log_group.ssm_logs,
    aws_kms_alias.ssm_key_alias
  ]
}
