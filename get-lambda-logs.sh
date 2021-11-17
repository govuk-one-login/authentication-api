#!/usr/bin/env bash
set -eu

pushd logs

LOG_GROUPS=$(docker-compose exec -T aws awslocal logs describe-log-groups)
for LOG_GROUP in $(echo -n "${LOG_GROUPS}" | jq -rc '.logGroups[].logGroupName'); do
  echo "Getting log group ${LOG_GROUP}..."
  mkdir -p ".${LOG_GROUP}"
    STREAMS=$(docker-compose exec -T aws awslocal logs describe-log-streams --log-group-name "${LOG_GROUP}")
    for LOG_STREAM in $(echo -n "${STREAMS}" | jq -rc '.logStreams[].logStreamName'); do
      echo "Downloading stream ${LOG_STREAM}..."
      FILENAME=$(echo -n "${LOG_STREAM}" | tr /\[\] -)

      docker-compose exec -T aws awslocal logs get-log-events --log-group-name "${LOG_GROUP}" --log-stream-name "${LOG_STREAM}" --output text > ".${LOG_GROUP}/${FILENAME}.log"
    done
done
popd
