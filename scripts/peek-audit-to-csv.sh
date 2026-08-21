#!/usr/bin/env bash
set -euo pipefail

# Peek at messages on an SQS queue and extract to CSV.
# Messages are returned to the queue after the visibility timeout (not deleted).

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat << EOF
Usage: $(basename "$0") [MAX_MESSAGES] [OUTPUT_FILE]

Peek at audit events from SQS queues and extract to CSV.
Messages are returned to the queue after the visibility timeout (not deleted).

Arguments:
  MAX_MESSAGES  Maximum messages to fetch per queue (default: 50)
  OUTPUT_FILE   Output CSV file path (default: audit-events.csv)

Options:
  -h, --help    Show this help message
EOF
  exit 0
}

[[ ${1:-} == "-h" || ${1:-} == "--help" ]] && usage

MAX_MESSAGES="${1:-50}"
OUTPUT_FILE="${2:-audit-events.csv}"

environments=("authdev1" "authdev2" "authdev3" "dev")

echo "Select environment:"
select env in "${environments[@]}"; do
  if [[ -n ${env} ]]; then
    ENVIRONMENT="${env}"
    break
  fi
  echo "Invalid selection. Please try again."
done

QUEUE_NAMES=(
  "${ENVIRONMENT}-auth-internal-api-txma-audit-queue"
  "${ENVIRONMENT}-auth-external-api-txma-audit-queue"
)
export AWS_PROFILE="di-authentication-development-AdministratorAccessPermission"

# shellcheck source=/dev/null
source "${DIR}/export_aws_creds.sh"

VISIBILITY_TIMEOUT=30
BATCH_SIZE=10
first=true
total_received=0

echo "Output: ${OUTPUT_FILE}"

for QUEUE_NAME in "${QUEUE_NAMES[@]}"; do
  QUEUE_URL=$(aws sqs get-queue-url --queue-name "${QUEUE_NAME}" --query 'QueueUrl' --output text 2> /dev/null) || {
    echo "Skipping ${QUEUE_NAME} (not found)"
    continue
  }
  echo "Peeking at up to ${MAX_MESSAGES} messages from: ${QUEUE_NAME}"

  received=0
  while [ "${received}" -lt "${MAX_MESSAGES}" ]; do
    remaining=$((MAX_MESSAGES - received))
    fetch=$((remaining < BATCH_SIZE ? remaining : BATCH_SIZE))

    response=$(aws sqs receive-message \
      --queue-url "${QUEUE_URL}" \
      --max-number-of-messages "${fetch}" \
      --visibility-timeout "${VISIBILITY_TIMEOUT}" \
      --message-attribute-names All \
      --attribute-names All 2> /dev/null)

    messages=$(echo "${response}" | jq -r '.Messages // [] | length')
    [ "${messages}" -eq 0 ] && break

    if [ "${first}" = true ]; then
      REST_COLS=$(echo "${response}" | jq -c '
        .Messages[0].Body | fromjson | walk(if type == "object" then del(.device_information, .timestamp) else . end)
        | [keys_unsorted[] | select(. != "event_name" and . != "event_timestamp_ms")]
      ')
      echo "${response}" | jq -r --argjson rest "${REST_COLS}" '
        ["event_name", "govuk_signin_journey_id", "event_timestamp_ms", "event_timestamp_readable"] + $rest | @csv
      ' > "${OUTPUT_FILE}"
      first=false
    fi

    echo "${response}" | jq -r --argjson rest "${REST_COLS}" '
      .Messages[].Body | fromjson | walk(if type == "object" then del(.device_information, .timestamp) else . end)
      | (first(.. | .govuk_signin_journey_id? // empty) // "") as $journey_id
      | ((.event_timestamp_ms // 0) | "\(. / 1000 | floor | strftime("%Y-%m-%d %H:%M:%S")).\(. % 1000)") as $readable_ts
      | . as $msg
      | [.event_name, $journey_id, .event_timestamp_ms, $readable_ts] + [$rest[] as $k | $msg[$k] // null | if type == "object" or type == "array" then tojson else . end]
      | @csv
    ' >> "${OUTPUT_FILE}"

    received=$((received + messages))
  done

  echo "  Got ${received} messages from ${QUEUE_NAME}"
  total_received=$((total_received + received))
done

echo "Extracted ${total_received} total messages to ${OUTPUT_FILE}"
