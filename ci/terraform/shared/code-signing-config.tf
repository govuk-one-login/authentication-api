resource "aws_lambda_code_signing_config" "code_signing_config" {
  allowed_publishers {
    signing_profile_version_arns = [
      var.di_tools_signing_profile_version_arn
    ]
  }

  description = "${var.environment}-code-signing-config"

  policies {
    untrusted_artifact_on_deployment = var.enforce_code_signing ? "Enforce" : "Warn"
  }
}