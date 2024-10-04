# ----------------------------------------------------------
# CodeDeploy resources
# ----------------------------------------------------------

resource "aws_codedeploy_app" "auth" {
  compute_platform = "Lambda"
  name             = replace("${var.environment}-${var.endpoint_name}", ".", "")
}

resource "aws_codedeploy_deployment_group" "auth" {
  app_name              = aws_codedeploy_app.auth.name
  deployment_group_name = "authDeploymentGroup"
  service_role_arn      = aws_iam_role.codedeploy_deployment_group_auth.arn

  deployment_config_name = var.skip_canary ? "CodeDeployDefault.LambdaAllAtOnce" : "CodeDeployDefault.LambdaLinear10PercentEvery1Minute"
  deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type   = "BLUE_GREEN"
  }

  auto_rollback_configuration {
    enabled = true
    events  = var.auto_rollback_events
  }

}

# ----------------------------------------------------------
# Trigger of deployment
# ----------------------------------------------------------

resource "null_resource" "run_codedeploy" {

  triggers = {
    lambda_version = var.lambda_version
  }

  provisioner "local-exec" {

    interpreter = var.interpreter
    command     = <<EOT
#!/bin/bash
if [ '${var.lambda_version}' == '${var.lambda_alias_version}' ]; then
  echo "Skipping deployment because target version (${var.lambda_version}) is already the current version"
  exit 0
fi
ID=$(${var.aws_cli_command} deploy create-deployment \
    --application-name ${aws_codedeploy_app.auth.name}  \
    --deployment-group-name ${aws_codedeploy_deployment_group.auth.deployment_group_name}  \
    --revision "{\"revisionType\":\"AppSpecContent\",\"appSpecContent\":{\"content\":\"{\\\"version\\\":0,\\\"Resources\\\":[{\\\"${var.lambda_function_name}\\\":{\\\"Type\\\":\\\"AWS::Lambda::Function\\\",\\\"Properties\\\":{\\\"Name\\\":\\\"${var.lambda_function_name}\\\",\\\"Alias\\\":\\\"${var.lambda_alias_name}\\\",\\\"CurrentVersion\\\":\\\"${var.lambda_alias_version}\\\",\\\"TargetVersion\\\":\\\"${var.lambda_version}\\\"}}}]}\"}}" \
    --output text \
    --query '[deploymentId]')
STATUS=$(${var.aws_cli_command} deploy get-deployment \
    --deployment-id $ID \
    --output text \
    --query '[deploymentInfo.status]')
while [[ $STATUS == "Created" || $STATUS == "InProgress" || $STATUS == "Pending" || $STATUS == "Queued" || $STATUS == "Ready" ]]; do
    echo "Status: $STATUS..."
    STATUS=$(${var.aws_cli_command} deploy get-deployment \
        --deployment-id $ID \
        --output text \
        --query '[deploymentInfo.status]')
    SLEEP_TIME=$((( $RANDOM % 5 ) + ${var.get_deployment_sleep_timer}))
    echo "Sleeping for: $SLEEP_TIME Seconds"
    sleep $SLEEP_TIME
done
${var.aws_cli_command} deploy get-deployment --deployment-id $ID
if [[ $STATUS == "Succeeded" ]]; then
    echo "Deployment succeeded."
else
    echo "Deployment failed!"
    exit 1
fi
EOT
  }

}

# ----------------------------------------------------------
# notify deployment Failure
# ----------------------------------------------------------

data "aws_cloudformation_export" "notifications" {
  count = var.code_deploy_notification ? 1 : 0
  name  = "${var.environment}-notifications-BuildNotificationTopicArn"
}

resource "aws_codestarnotifications_notification_rule" "auth" {
  count          = var.code_deploy_notification ? 1 : 0
  detail_type    = "BASIC"
  event_type_ids = ["codedeploy-application-deployment-failed"]

  name     = replace("${var.environment}-${var.endpoint_name}-notify", ".", "")
  resource = aws_codedeploy_app.auth.arn

  target {
    address = data.aws_cloudformation_export.notifications[0].value
  }
}
