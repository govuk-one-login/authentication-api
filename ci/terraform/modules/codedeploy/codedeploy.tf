# ----------------------------------------------------------
# CodeDeploy resources
# ----------------------------------------------------------

resource "aws_codedeploy_app" "auth" {
  compute_platform = "Lambda"
  name             = replace("${var.environment}-${var.endpoint_name}-auth", ".", "")
}

resource "aws_codedeploy_deployment_group" "auth" {
  app_name              = aws_codedeploy_app.auth.name
  deployment_group_name = "authDeploymentGroup"
  service_role_arn      = aws_iam_role.codedeploy_deployment_group_auth.arn

  deployment_config_name = "CodeDeployDefault.LambdaLinear10PercentEvery1Minute"
  deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type   = "BLUE_GREEN"
  }
}

# ----------------------------------------------------------
# Trigger of deployment
# ----------------------------------------------------------

locals {
  # AWS CodeDeploy can't deploy when CurrentVersion is "$LATEST"

  appspec = merge({
    version = "0.0"
    Resources = [
      {
        "${var.lambda_function_name}" = {
          Type = "AWS::Lambda::Function"
          Properties = {
            Name           = var.lambda_function_name
            Alias          = var.lambda_alias_name
            CurrentVersion = var.lambda_alias_version
            TargetVersion  = var.lambda_version
          }
        }
      }
    ]
    }
  )

  appspec_content = replace(jsonencode(local.appspec), "\"", "\\\"")
  appspec_sha256  = sha256(jsonencode(local.appspec))

  script = <<EOF
#!/bin/bash

if [ '${var.lambda_version}' == '${var.lambda_alias_version}' ]; then
  echo "Skipping deployment because target version (${var.lambda_version}) is already the current version"
  exit 0
fi

ID=$(${var.aws_cli_command} deploy create-deployment \
    --application-name ${aws_codedeploy_app.auth.name}  \
    --deployment-group-name ${aws_codedeploy_deployment_group.auth.deployment_group_name}  \
    --revision '{"revisionType": "AppSpecContent", "appSpecContent": {"content": "${local.appspec_content}", "sha256": "${local.appspec_sha256}"}}' \
    --output text \
    --query '[deploymentId]')

%{if var.wait_deployment_completion}
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

%{else}

${var.aws_cli_command} deploy get-deployment --deployment-id $ID
echo "Deployment started, but wait deployment completion is disabled!"

%{endif}
EOF

}


resource "local_file" "deploy_script" {
  filename             = "deploy_script_${local.appspec_sha256}.txt"
  directory_permission = "0755"
  file_permission      = "0644"
  content              = local.script
}

resource "null_resource" "run_codedeploy" {

  triggers = {
    lambda_version = var.lambda_version
  }

  provisioner "local-exec" {
    command     = local.script
    interpreter = var.interpreter
  }

}

####Simple deployment this will be errored if lambda changes every deployment 
#resource "null_resource" "run_codedeploy" {
#  triggers = {
    # Run codedeploy when lambda version is updated
#    lambda_version = var.lambda_version
#  }

#  provisioner "local-exec" {
#    # Only trigger deploy when lambda version is updated (-gt lambda Alias version)
#    command = "if [ ${var.lambda_version} -gt ${var.lambda_alias_version} ] ;then aws deploy create-deployment --application-name ${aws_codedeploy_app.auth.name} --deployment-group-name ${aws_codedeploy_deployment_group.auth.deployment_group_name} --revision '{\"revisionType\":\"AppSpecContent\",\"appSpecContent\":{\"content\":\"{\\\"version\\\":0,\\\"Resources\\\":[{\\\"${var.lambda_function_name}\\\":{\\\"Type\\\":\\\"AWS::Lambda::Function\\\",\\\"Properties\\\":{\\\"Name\\\":\\\"${var.lambda_function_name}\\\",\\\"Alias\\\":\\\"${var.lambda_alias_name}\\\",\\\"CurrentVersion\\\":\\\"${var.lambda_alias_version}\\\",\\\"TargetVersion\\\":\\\"${var.lambda_version}\\\"}}}]}\"}}';fi"
#  }
#}