#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
cd "${DIR}" || exit 1

if [ $# -ne 2 ]; then
  echo "Usage: export-ics.sh email environment"
  exit 1
fi

export AWS_REGION=eu-west-2

if [[ $2 == authdev* ]]; then
  sector="identity.$2.dev.account.gov.uk"
else
  sector="identity.$2.account.gov.uk"
fi

echo -e "Exporting internalCommonSubjectId for Email = $1 Environment = $2 Sector = ${sector}"

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
