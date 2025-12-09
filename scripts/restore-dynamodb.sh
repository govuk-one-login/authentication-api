#!/usr/bin/env bash
set -euo pipefail

AWS_PROFILE="${1:-}"
TABLE_NAME="${2:-}"
BACKUP_ARN="${3:-}"
TABLE_EXISTS="${4:-1}"
AWS_REGION="${6:-${AWS_REGION:-eu-west-2}}"

export AWS_REGION=${AWS_REGION}
export AWS_PROFILE=${AWS_PROFILE}

function sso_login() {
  if ! aws sts get-caller-identity &> /dev/null; then
    aws sso login --profile "${AWS_PROFILE}"
  fi
}

if [[ -z ${TABLE_NAME} || -z ${BACKUP_ARN} || -z ${AWS_ACCOUNT} ]]; then
  echo "Usage: $0 <aws-profile> <table-name> <backup-arn> [0|1] [aws-region]" >&2
  exit 1
fi

read -r -p "Have you STOPPED Terraform auto-apply? [y/N] " ans
ans="$(printf "%s" "${ans}" | tr '[:upper:]' '[:lower:]')"

if [ "${ans}" != "y" ]; then
  echo "Abort: please stop auto-apply first."
  exit 1
fi

sso_login

echo "Fetching current table encryption (KMS) settings..."
KMS_KEY_ARN="$(
  aws dynamodb describe-table \
    --table-name "${TABLE_NAME}" \
    --query 'Table.SSEDescription.KMSMasterKeyArn' \
    --output text \
    --profile "${AWS_PROFILE}" 2> /dev/null || true
)"

SSE_OVERRIDE=""
SSE_ARGS=()

if [[ -z ${KMS_KEY_ARN} || ${KMS_KEY_ARN} == "None" ]]; then
  echo "No customer-managed KMS key detected on the table (likely using AWS-owned/default key)."
  read -r -p "Enter KMS key ARN/ID to use for RESTORE (or press Enter to use backup's default encryption): " KMS_KEY_ARN
  if [[ -n ${KMS_KEY_ARN} ]]; then
    SSE_OVERRIDE="Enabled=true,SSEType=KMS,KMSMasterKeyId=${KMS_KEY_ARN}"
  fi
else
  echo "Detected KMS key ARN: ${KMS_KEY_ARN}"
  SSE_OVERRIDE="Enabled=true,SSEType=KMS,KMSMasterKeyId=${KMS_KEY_ARN}"
fi

if [[ -n ${SSE_OVERRIDE} ]]; then
  echo "Will restore using SSE override: ${SSE_OVERRIDE}"
  SSE_ARGS=(--sse-specification-override "${SSE_OVERRIDE}")
else
  echo "Will restore using encryption settings from the backup (no SSE override)."
fi
echo

echo "=== DynamoDB restore ==="
echo "AWS Account:  ${AWS_ACCOUNT}"
echo "AWS Profile:  ${AWS_PROFILE}"
echo "AWS region:   ${AWS_REGION}"
echo "Table:        ${TABLE_NAME}"
echo "Table Exists: ${TABLE_EXISTS}"
echo "Backup:       ${BACKUP_ARN}"
echo "Encryption:   ${KMS_KEY_ARN}"
echo

read -r -p "Is this Correct [y/N] " ans
ans="$(printf "%s" "${ans}" | tr '[:upper:]' '[:lower:]')"

if [ "${ans}" != "y" ]; then
  echo "Aborted!"
  exit 1
fi

if [[ ${TABLE_EXISTS} -eq 1 ]]; then
  echo "Table Exists, backing up and disabling delete protection"
  BACKUP_NAME="${TABLE_NAME}_manual_$(date -u +%Y%m%dT%H%M%S)"
  echo "Creating on-demand backup: ${BACKUP_NAME}"
  _BACKUP_ARN="$(
    aws dynamodb create-backup \
      --table-name "${TABLE_NAME}" \
      --backup-name "${BACKUP_NAME}" \
      --query 'BackupDetails.BackupArn' \
      --output text \
      --profile "${AWS_PROFILE}"
  )"
  echo "Backup ARN: ${BACKUP_NAME} (${_BACKUP_ARN})"
  echo

  echo "Disabling Delete Protection on: ${AWS_ACCOUNT} - ${AWS_REGION} - ${TABLE_NAME}"
  aws dynamodb update-table \
    --table-name "${TABLE_NAME}" \
    --no-deletion-protection-enabled \
    --profile "${AWS_PROFILE}" > /dev/null

  sleep 5
  aws dynamodb wait table-exists --table-name "${TABLE_NAME}" \
    --profile "${AWS_PROFILE}"

  echo "Deleting: ${AWS_ACCOUNT} - ${AWS_REGION} - ${TABLE_NAME}"
  aws dynamodb delete-table \
    --table-name "${TABLE_NAME}" \
    --profile "${AWS_PROFILE}" > /dev/null

fi
aws dynamodb wait table-not-exists \
  --table-name "${TABLE_NAME}" \
  --profile "${AWS_PROFILE}"

echo "Restoring table ${TABLE_NAME} from backup: ${BACKUP_ARN}"
aws dynamodb restore-table-from-backup \
  --target-table-name "${TABLE_NAME}" \
  --backup-arn "${BACKUP_ARN}" \
  "${SSE_ARGS[@]}" \
  --profile "${AWS_PROFILE}" > /dev/null
aws dynamodb wait table-exists --table-name "${TABLE_NAME}" \
  --profile "${AWS_PROFILE}"

echo "Enabling Delete Protection on: ${AWS_ACCOUNT} - ${AWS_REGION} - ${TABLE_NAME}"
aws dynamodb update-table \
  --table-name "${TABLE_NAME}" \
  --deletion-protection-enabled \
  --profile "${AWS_PROFILE}" > /dev/null

echo "Re-Apply Terraform to attach Roles and re-enabled delete protection"
