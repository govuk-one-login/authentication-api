#!/bin/bash
set -euo pipefail

# Ensure we are in the directory of the script
cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 || exit

# Fail fast if AWS_PROFILE is not set
if [ -z "${AWS_PROFILE}" ]; then
  echo "AWS_PROFILE environment variable not set. Exiting." >&2
  exit 1
fi

# Authenticates the terminal with the AWS account
function aws_credentials {
  # Test if the AWS CLI is configured with the correct profile
  if ! sso_session="$(aws configure get sso_session)"; then
    echo "AWS CLI profile ${AWS_PROFILE} is not configured."
    echo "Please visit https://govukverify.atlassian.net/wiki/x/UAFl4 for instructions."
    exit 1
  fi
  if ! aws sts get-caller-identity > /dev/null; then
    aws sso login --sso-session "${sso_session}"
  fi

  configured_region="$(aws configure get region 2> /dev/null || true)"
  export AWS_REGION="${configured_region:-eu-west-2}"
}

function stack_exists {
  local stack_name="$1"

  stack_state=$(aws cloudformation describe-stacks \
    --stack-name "${stack_name}" \
    --query "Stacks[0].StackStatus" --output text || echo "NO_STACK")

  if [[ ${stack_state} == "NO_STACK" ]]; then
    return 1
  elif [[ ${stack_state} == "ROLLBACK_COMPLETE" ]]; then
    echo "Deleting stack ${stack_name} (in ROLLBACK_COMPLETE state) ..."
    aws cloudformation delete-stack --stack-name "${stack_name}"
    aws cloudformation wait stack-delete-complete --stack-name "${stack_name}"
    return 1
  else
    return 0
  fi
}

# Creates the CloudFormation stack if it doesnt already exist
function create_stack {
  local stack_name="$1"
  local template_path="$2"
  local parameters_file="$3"
  local tags_file="$4"

  if ! [[ ${template_path} =~ "file://" ]]; then
    template_path="file://${template_path}"
  fi

  echo "Creating new stack ${stack_name}"
  aws cloudformation create-stack \
    --stack-name="${stack_name}" \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --template-body="${template_path}" \
    --parameters="$(jq '. | tojson' -r "${parameters_file}")" \
    --tags="$(jq '. | tojson' -r "${tags_file}")"

  # Wait until change set creation is completed
  aws cloudformation wait stack-create-complete \
    --stack-name="${stack_name}"

  echo "Create complete"
}

# Creates a changeset for the CloudFormation stack that will be updated
function create_change_set {
  local stack_name="$1"
  local change_set_name="$2"
  local template_path="$3"
  local parameters_file="$4"
  local tags_file="$5"

  if ! [[ ${template_path} =~ "file://" ]]; then
    template_path="file://${template_path}"
  fi

  echo "Creating ${change_set_name} change set"
  aws cloudformation create-change-set \
    --stack-name="${stack_name}" \
    --change-set-name="${change_set_name}" \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --template-body="${template_path}" \
    --parameters="$(jq '. | tojson' -r "${parameters_file}")" \
    --tags="$(jq '. | tojson' -r "${tags_file}")"

  # Wait until change set creation is completed
  if ! aws cloudformation wait change-set-create-complete \
    --stack-name="${stack_name}" \
    --change-set-name="${change_set_name}"; then

    echo "The change set produced no changes." >&2
    return 1
  fi

  echo "Change set successfully created." >&2
  return 0
}

function describe_change_set {

  local stack_name="$1"
  local change_set_name="$2"
  local output_format="table"
  if [ $# -gt 2 ]; then
    output_format="$3"
  fi

  if [[ ${output_format} != "json" ]]; then
    echo "${change_set_name} changes:"
  fi

  aws cloudformation describe-change-set \
    --change-set-name "${change_set_name}" \
    --stack-name "${stack_name}" \
    --query 'Changes[].ResourceChange.{Action: Action, LogicalResourceId: LogicalResourceId, PhysicalResourceId: PhysicalResourceId, ResourceType: ResourceType, Replacement: Replacement}' \
    --output "${output_format}"
}

# Updates the Cloudformation stack using the changeset created above
function execute_change_set {

  local stack_name="$1"
  local change_set_name="$2"

  echo "Applying changes to stack ${stack_name} ..."
  aws cloudformation execute-change-set \
    --change-set-name "${change_set_name}" \
    --stack-name "${stack_name}"

  # Wait until stack update is completed
  aws cloudformation wait stack-update-complete \
    --stack-name "${stack_name}"

  echo "Update to stack ${stack_name} completed successfully."
}

# Prints the stack outputs after the update is complete
function get_stack_outputs {

  local stack_name="$1"
  local output_format="table"
  if [ $# -gt 1 ]; then
    output_format="$2"
  fi

  if [[ ${output_format} != "json" ]]; then
    echo "${stack_name} outputs:"
  fi

  aws cloudformation describe-stacks \
    --stack-name "${stack_name}" \
    --query 'Stacks[0].Outputs[].{key: OutputKey, value: OutputValue, export: ExportName}' \
    --output "${output_format}"
}

function main {

  if [ $# -lt 3 ]; then
    echo "Usage: $0 <AWS_ACCOUNT> <STACK_NAME> <TEMPLATE_PATH>"
    echo "Please see README.md for more information."
    exit 1
  fi

  # Input parameters
  AWS_ACCOUNT="${1}"
  STACK_NAME="${2}"
  TEMPLATE_PATH="${3}"

  if [ ! -f "${TEMPLATE_PATH}" ]; then
    echo "Could not find template at path: ${TEMPLATE_PATH}"
    exit 1
  fi

  # Defaults
  PARAMETERS_FILE="${PARAMETERS_FILE:=./configuration/${AWS_ACCOUNT}/${STACK_NAME}/parameters.json}"
  TAGS_FILE="${TAGS_FILE:=./configuration/${AWS_ACCOUNT}/tags.json}"
  STACK_TAGS_FILE="${STACK_TAGS_FILE:=./configuration/${AWS_ACCOUNT}/${STACK_NAME}/tags.json}"

  if [ ! -f "${PARAMETERS_FILE}" ]; then
    echo "Configuration file not found. Please see README.md"
    exit 1
  fi

  # Variables
  DATE="$(date "+%Y%m%d%H%M%S")"
  CHANGE_SET_NAME="${STACK_NAME}-${DATE}"

  if [ ! -f "${PARAMETERS_FILE}" ]; then
    echo "Configuration file not found. Please see README.md"
    exit 1
  fi

  if [ ! -f "${TAGS_FILE}" ]; then
    echo "Tags file not found. Please see README.md"
    exit 1
  fi

  if [ -f "${STACK_TAGS_FILE}" ]; then
    tmp_tags_file="$(mktemp)"
    jq -s 'add | group_by(.Key) | map(last)' "${TAGS_FILE}" "${STACK_TAGS_FILE}" > "${tmp_tags_file}"
    TAGS_FILE="${tmp_tags_file}"
  fi

  # Skip authentication if terminal is already authenticated
  if [ "${SKIP_AWS_AUTHENTICATION:=false}" != "true" ]; then
    aws_credentials
  fi

  echo "Using template at path: ${TEMPLATE_PATH}"

  if stack_exists "${STACK_NAME}"; then
    if create_change_set "${STACK_NAME}" "${CHANGE_SET_NAME}" "${TEMPLATE_PATH}" "${PARAMETERS_FILE}" "${TAGS_FILE}"; then # True if there is an existing stack.
      if [ "${AUTO_APPLY_CHANGESET:=false}" = "false" ]; then                                                              # This defaults to false if not set.
        describe_change_set "${STACK_NAME}" "${CHANGE_SET_NAME}"
        while true; do
          read -rp "Apply change set ${CHANGE_SET_NAME}? [y/n] " apply_changeset # Script will abort the update and exit unless user selects Y.
          case ${apply_changeset} in
            [nN])
              echo "Aborting template."
              exit 0
              ;;
            [yY]) break ;;
            *) echo invalid response, please use Y/y or N/n ;;
          esac
        done
      fi
      execute_change_set "${STACK_NAME}" "${CHANGE_SET_NAME}"
    fi
  else
    create_stack "${STACK_NAME}" "${template_path}" "${PARAMETERS_FILE}" "${TAGS_FILE}" # Creates a new stack
  fi
  get_stack_outputs "${STACK_NAME}" # Print the stack outputs
}

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  main "$@"
else
  echo "This script should be executed, not sourced" >&2
  exit 1
fi
