#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(dirname "$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)")"
CONFIG_FILE="${REPO_ROOT}/.tflint.hcl"

declare -A directories
declare -a tflint_args
for arg in "${@}"; do
  if [[ -f ${arg} ]]; then
    dir="$(dirname "${arg}")"
    filename="$(basename "${arg}")"

    if [[ -n ${directories["${dir}"]:-} ]]; then
      directories["${dir}"]+=" ${filename}"
      continue
    fi
    directories["$(dirname "${arg}")"]="${filename}"
  elif [[ ${arg} == "-"* ]]; then
    tflint_args+=("${arg}")
  fi
done

if ! init="$(tflint --config "${CONFIG_FILE}" --init)"; then
  status=$?
  echo "${init}"
  exit ${status}
fi

declare -A pids
for dir in "${!directories[@]}"; do
  filter=()
  for file in ${directories["${dir}"]}; do
    filter+=("--filter=${file}")
  done
  tflint --config "${CONFIG_FILE}" --chdir "${dir}" --fix "${tflint_args[@]}" "${filter[@]}" &
  pids["${dir}"]=$!
done

wait "${pids[@]}"
