#!/usr/bin/env bash
set -eo pipefail

# This script waits for the alias of a Lambda function to be updated.
# It polls the Lambda API to get the routing configuration of the alias. If the routing configuration is null, it means the alias has been updated.
# The script will exit successfully if the alias is updated within the total timeout.
# If the alias is not updated within the total timeout, the script will exit with an error.
# If the aws calls fail for any reason, the script will retry up to MAX_FAILURES times before exiting with an error.
# The script will sleep for (ATTEMPT_TIMEOUT-time_to_run_last_attempt) seconds between each attempt. This means that
# we should expect the script to run every ATTEMPT_TIMEOUT seconds.

# Although `$TOTAL TIMEOUT` is passed into this script, it's not actually used in the script for timeout purposes.
# As this script will only be called by terraform, it's easier to print this value within the script than within
# the bash one-liner in the HCL data block. If this script is not wrapped within `timeout` bash command, it will
# run indefinitely.

FUNCTION_NAME=${1}
ALIAS_NAME=${2}
TOTAL_TIMEOUT=${3}

ATTEMPT_TIMEOUT="$(printf "%.0f" "${4:-5}")"
MAX_FAILURES="$(printf "%.0f" "${5:-5}")"

function usage() {
  echo "Usage: $0 <function_name> <alias_name> <total_timeout> [attempt_timeout] [max_failures]"
  echo "  function_name: Name of the Lambda function"
  echo "  alias_name: Name of the alias"
  echo "  total_timeout: Total time to wait for the alias to be updated (in seconds) (only used for logging)"
  echo "  attempt_timeout: Time to wait for each attempt to get the routing config (default: 5 seconds)"
  echo "  max_failures: Maximum number of failures before exiting (default: 5)"
  exit 1
}

if [[ $# -lt 3 ]]; then
  usage
fi

DATE_CMD="date"
DATE_FMT="%s.%N"

if [[ ${OSTYPE} == "darwin"* ]]; then
  if command -v gdate &> /dev/null; then
    DATE_CMD="gdate"
  else
    DATE_FMT="%s"
  fi
fi

function get_timestamp() {
  ${DATE_CMD} +"${DATE_FMT}"
}

function awksubtract() {
  awk "BEGIN {print ${1} - ${2}}"
}

function log() {
  echo "$(date +"%Y-%m-%d %H:%M:%S") - $*"
}

function get_routing_config() {
  local function_name="${1}"
  local alias_name="${2}"

  aws --cli-connect-timeout "${ATTEMPT_TIMEOUT}" lambda get-alias --function-name "${function_name}" --name "${alias_name}" --query 'RoutingConfig' --output json
}

finish_seconds="$(awk "BEGIN { printf \"%s\", $(date "+%s") + ${TOTAL_TIMEOUT} }")"
finish_datetime=""
if [[ ${OSTYPE} == "darwin"* ]]; then
  finish_datetime="$(date -u -r "${finish_seconds}" +%T%z)"
else
  finish_datetime="$(date -u -d "@${finish_seconds}" +%T%z)"
fi

log "Waiting until ${finish_datetime} for alias to be updated (timeout: ${TOTAL_TIMEOUT}s)" >&2

failure_count=0
while true; do
  start_time=$(get_timestamp)
  if routing_config="$(get_routing_config "${FUNCTION_NAME}" "${ALIAS_NAME}")"; then
    # If the output of `get_routing_config` is "null", it means the alias has been updated and we can break out of the while loop and exit successfully.
    if [[ ${routing_config} == "null" ]]; then
      break
    fi

  else
    failure_count=$((failure_count + 1))
    if [[ ${failure_count} -ge ${MAX_FAILURES} ]]; then
      log "!! Reached maximum number of failures (${MAX_FAILURES})" >&2
      exit 1
    else
      log "!! Failed to get routing config for alias ${ALIAS_NAME} of function ${FUNCTION_NAME} (attempt ${failure_count}/${MAX_FAILURES})" >&2
    fi
  fi
  sleep_time="$(awk "BEGIN { printf \"%.1f\", ${ATTEMPT_TIMEOUT} - ($(get_timestamp) - ${start_time}) }")"
  if [[ $(printf "%.0f" "${sleep_time}") -gt 0 ]]; then
    sleep "${sleep_time}"
  fi
done

log "Alias successfully updated"
