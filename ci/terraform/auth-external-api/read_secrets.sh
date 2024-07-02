#!/usr/bin/env bash
set -euo pipefail

[[ "${BASH_SOURCE[0]}" != "${0}" ]] || {
  echo "Error: Script must be sourced, not executed"
  exit 1
}

ENVIRONMENT="${1}"

if [ "$ENVIRONMENT" = "dev" ]; then
  ENVIRONMENT="build"
fi

function get_page() {
  local next_token="${1:-}"

  if [ -n "${next_token}" ]; then
    next_token="--next-token=${next_token}"
  fi

  aws secretsmanager batch-get-secret-value --filters 'Key=name,Values=/deploy/'"${ENVIRONMENT}"'/' --max-results 20 "${next_token}"

}

function get_page_secrets() {
  jq -r '[.SecretValues[]|{name: (.Name|split("/")|last), value: .SecretString}]'
}

function get_next_token() {
  jq -r '.NextToken // empty'
}

first_page="$(get_page)"

SECRETS="$(get_page_secrets <<<"${first_page}")"

next_token="$(get_next_token <<<"${first_page}")"
while [ -n "${next_token}" ]; do
  page="$(get_page "${next_token}")"
  page_secrets="$(get_page_secrets <<<"${page}")"
  SECRETS="$(jq -n --argjson secrets "${SECRETS}" --argjson page_secrets "${page_secrets}" '$secrets + $page_secrets')"
  next_token="$(get_next_token <<<"${page}")"
done

while IFS=$'\t' read -r name value; do
  export "TF_VAR_${name}"="${value}"
done < <(jq -r '.[]|[.name, .value]|@tsv' <<<"${SECRETS}")
