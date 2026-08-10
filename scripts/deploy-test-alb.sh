#!/bin/bash

set -e

STACK_NAME="auth-test-alb"
TEMPLATE_FILE="alb-to-private-api.yaml"
VPC_STACK_NAME="${1:-vpc}"

# Set AWS profile and load credentials
export AWS_PROFILE="di-authentication-development-AdministratorAccessPermission"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find project root (assuming it's a git repository)
PROJECT_ROOT="$(git rev-parse --show-toplevel 2> /dev/null || echo "${DIR}/..")"

# shellcheck disable=SC1091
source "${DIR}/export_aws_creds.sh"

echo "Deploying CloudFormation stack: ${STACK_NAME}"
echo "VPC Stack: ${VPC_STACK_NAME}"

aws cloudformation deploy \
  --template-file "${PROJECT_ROOT}/ci/cloudformation/test-alb-account-mgmt/${TEMPLATE_FILE}" \
  --stack-name "${STACK_NAME}" \
  --parameter-overrides \
  VpcStackName="${VPC_STACK_NAME}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region eu-west-2

echo "Stack deployment complete!"
