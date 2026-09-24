#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

export ENVIRONMENT="${1:-}"

if [[ -z ${ENVIRONMENT} ]]; then
  echo "Usage: $0 <environment>"
  exit 1
fi

if [[ ${ENVIRONMENT} == authdev* ]] || [[ ${ENVIRONMENT} == "dev" ]]; then
  export AWS_PROFILE="di-auth-development-admin"
elif [ "${ENVIRONMENT}" == "build" ] || [ "${ENVIRONMENT}" == "integration" ]; then
  export AWS_PROFILE="gds-di-development-admin"
elif [ "${ENVIRONMENT}" == "staging" ]; then
  export AWS_PROFILE="di-auth-staging-admin"
elif [ "${ENVIRONMENT}" == "production" ]; then
  export AWS_PROFILE="gds-di-production-admin"
else
  echo "Unknown environment: ${ENVIRONMENT}"
  exit 1
fi

# shellcheck source=scripts/export_aws_creds.sh
source "${DIR}/export_aws_creds.sh"

mapfile -t function_names < <(aws lambda list-functions --max-items 10000 --query "Functions[?starts_with(FunctionName, '${ENVIRONMENT}-')].FunctionName" --output text | sed 's/\t/\n/g')

for function_name in "${function_names[@]}"; do
  if routing_config="$(aws lambda get-alias --function-name "${function_name}" --name "${function_name}-active" 2> /dev/null | jq --exit-status '.RoutingConfig' 2> /dev/null)"; then
    correct_version="$(echo "${routing_config}" | jq -r '.AdditionalVersionWeights | keys | .[0]')"
    aws lambda update-alias --function-name "${function_name}" --name "${function_name}-active" --function-version "${correct_version}" --routing-config AdditionalVersionWeights={} > /dev/null
    echo "Pointed broken alias ${function_name}-active to version ${correct_version}"
  fi
done
