#!/usr/bin/env bash

set -eu

if [ $# -ne 2 ]; then
  echo "Usage: export-ics.sh email environment"
  exit 1
fi

export AWS_REGION=eu-west-2

sector="identity.$2.account.gov.uk"

echo -e "Exporting internalCommonSubjectId for Email = $1 Environment = $2 Sector = ${sector}"

if [[ -z ${AWS_ACCESS_KEY_ID:-} || -z ${AWS_SECRET_ACCESS_KEY:-} ]]; then
  echo "!! AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set in the environment." >&2
  echo "!! Perhaps you meant: gds aws digital-identity-dev -- ${0}" >&2
  exit 1
fi

up="$(
  aws dynamodb get-item \
    --table-name "$2-user-profile" \
    --key "{\"Email\": {\"S\": \"$1\"}}" \
    --projection-expression "#E, #ST, #S, #PS, #LS" \
    --expression-attribute-names '{"#E": "Email", "#ST": "salt", "#S": "SubjectID", "#PS": "PublicSubjectID", "#LS": "LegacySubjectId"}' \
    --region "${AWS_REGION}" \
    --no-paginate
)"

if [ -n "${up}" ]; then
  ics="$(echo -n "${up}" | jq -r '.Item.SubjectID.S')"
  salt="$(echo -n "${up}" | jq -r '.Item.salt.B')"

  node -e "const { calculatePairwiseIdentifier } = require('./utils'); console.log(calculatePairwiseIdentifier('${ics}', '${sector}', '${salt}'))"
else
  echo "Email address $1 does not exist in $2 environment"
fi
