#!/usr/bin/env bash
ENVIRONMENT="authdev1"
functions="$(aws lambda list-functions --max-items 10000 --query "Functions[?starts_with(FunctionName, '${ENVIRONMENT}-')].FunctionName" --output text | sed 's/\t/\n/g')"
IFS=$'\n'

for function in ${functions}; do
  # aws lambda get-alias --function-name "${function}" --name "${function}-active" &>/dev/null || continue
  alias="$(aws lambda get-alias --function-name "${function}" --name "${function}-active" 2> /dev/null)" || continue # lambda doesn't have a well-known alias
  echo "${alias}" | jq --exit-status '.RoutingConfig' &> /dev/null || continue                                       # lambda isn't broken
  good_version="$(echo "${alias}" | jq -r '.RoutingConfig.AdditionalVersionWeights | keys | .[0]')"
  echo "${function} ${good_version}"
  aws lambda update-alias --function-name "${function}" --name "${function}-active" --function-version "${good_version}" --routing-config AdditionalVersionWeights={}
done
