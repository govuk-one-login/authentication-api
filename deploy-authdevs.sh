#!/usr/bin/env bash
set -euo pipefail

envvalue=("authdev1" "authdev2" "authdev3")

select word in "${envvalue[@]}"; do
  if [[ -z ${word} ]]; then
    printf '"%s" is not a valid choice\n' "${REPLY}" >&2
  else
    user_in="$((REPLY - 1))"
    break
  fi
done

for ((i = 0; i < ${#envvalue[@]}; ++i)); do
  if ((i == user_in)); then
    printf 'You picked "%s"\n' "${envvalue[${i}]}"
    DEPLOY_ENV=${envvalue[${i}]}
    printf "Deploying in environment %s\n" "${DEPLOY_ENV}"
    read -r -p "Press enter to continue or Ctrl+C to abort"
  fi
done

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

exec "${DIR}/deploy-dev.sh" "${DEPLOY_ENV}" "${@}"
