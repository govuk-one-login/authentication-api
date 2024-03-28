#!/bin/bash

set -eu

export DEPLOY_ENV="dev"
export AWS_PROFILE="orchestration-dev-admin"

parameters=$(jq -r '.[] | "\(.ParameterKey)=\(.ParameterValue)"' ./ci/stack-orchestration/dev/parameters.json)
echo "${parameters}"
echo "Deploying..."
sam build
sam deploy --stack-name dev-orch-be-deploy --template-file template.yaml --parameter-overrides Parameters="${parameters}" --no-fail-on-empty-changeset --capabilities CAPABILITY_NAMED_IAM --s3-bucket dev-orch-be-deploy-bucket

