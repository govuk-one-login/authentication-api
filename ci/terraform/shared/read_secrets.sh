#!/bin/bash
ENVIRONMENT=$1

if [ "$ENVIRONMENT" = "dev" ]; then
	ENVIRONMENT="build";
fi

secrets=$(aws secretsmanager list-secrets --filter Key="name",Values="/deploy/$ENVIRONMENT/" --region eu-west-2 | jq -c '.SecretList[]')

for i in $secrets; do
  arn=$(echo $i | jq -r '.ARN')
  name=$(echo $i | jq -r '.Name | split("/") | last')
  value=$(aws secretsmanager get-secret-value --secret-id $arn --region eu-west-2 | jq -r '.SecretString')
  VAR=(TF_VAR_$name=$value)
  export $VAR
done

TEST_CLIENT_EMAIL_ALLOWLIST=$(aws secretsmanager get-secret-value \
	--secret-id test-client-email-allowlist \
	--region eu-west-2 \
	| jq --raw-output '.SecretString' | jq -r '."test-client-email-allowlist"'
)

export TF_VAR_test_client_email_allowlist=$TEST_CLIENT_EMAIL_ALLOWLIST
