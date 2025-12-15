#!/bin/bash

set -e

STACK_NAME="mm-api-dev-access"
TEMPLATE_FILE="mm-api-dev-access.yaml"
ENVIRONMENT="${1:-dev}"
VPC_STACK_NAME="${2:-vpc}"

# Set AWS profile and load credentials
export AWS_PROFILE="di-authentication-development-AdministratorAccessPermission"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find project root (assuming it's a git repository)
PROJECT_ROOT="$(git rev-parse --show-toplevel 2> /dev/null || echo "${DIR}/..")"

# shellcheck disable=SC1091
source "${DIR}/export_aws_creds.sh"

echo "Deploying CloudFormation stack: ${STACK_NAME}"
echo "Environment: ${ENVIRONMENT}"
echo "VPC Stack: ${VPC_STACK_NAME}"

aws cloudformation deploy \
  --template-file "${PROJECT_ROOT}/ci/cloudformation/bastion/${TEMPLATE_FILE}" \
  --stack-name "${STACK_NAME}" \
  --parameter-overrides \
  Environment="${ENVIRONMENT}" \
  VpcStackName="${VPC_STACK_NAME}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region eu-west-2

echo "Stack deployment complete!"
# shellcheck disable=SC2016
echo "Instance ID: $(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --query 'Stacks[0].Outputs[?OutputKey==`DeveloperProxyInstanceId`].OutputValue' --output text --region eu-west-2)"
