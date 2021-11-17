#!/usr/bin/env bash
set -eu

pushd logs
LOG_GROUPS=$(docker-compose exec -T aws awslocal logs describe-log-groups | jq -r '.logGroups[].logGroupName')
while IFS= read -r LOG_GROUP; do
  echo "Getting log group ${LOG_GROUP}..."
  mkdir -p ".${LOG_GROUP}"
  STREAMS=$(docker-compose exec -T aws awslocal logs describe-log-streams --log-group-name "${LOG_GROUP}" | jq -r '.logStreams[].logStreamName')
  if [[ -n ${LOG_GROUP} ]]; then
    while IFS= read -r LOG_STREAM; do
      echo "Downloading stream ${LOG_STREAM}..."
      FILENAME=$(echo -n "${LOG_STREAM}" | tr /\[\] -)

      if [[ -n ${FILENAME} ]]; then
        docker-compose exec -T aws awslocal logs get-log-events --log-group-name "${LOG_GROUP}" --log-stream-name "${LOG_STREAM}" --output text > ".${LOG_GROUP}/${FILENAME}.log"
      fi
    done <<< "${STREAMS}"
  fi
done <<< "${LOG_GROUPS}"
popd
