### Signing key access for Authentication to send signed token response to Orchestration
data "aws_iam_policy_document" "auth_id_token_signing_kms_policy_document" {
  statement {
    sid    = "AllowAccessToKmsSigningKey"
    effect = "Allow"

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = [
      local.auth_id_token_signing_key_arn
    ]
  }
}

resource "aws_iam_policy" "auth_id_token_signing_kms_policy" {
  name_prefix = "kms-auth-to-orch-policy"
  path        = "/${var.environment}/auth-to-orch-kms-signing/"
  description = "IAM policy for managing Auth Token API's KMS key access to sign response to Orchestration"

  policy = data.aws_iam_policy_document.auth_id_token_signing_kms_policy_document.json
}
