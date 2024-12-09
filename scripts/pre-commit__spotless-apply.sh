#!/usr/bin/env bash
set -euo pipefail

if [ "${PRE_COMMIT:-0}" -ne 1 ]; then
  echo "This script should only be run by pre-commit! Exiting." >&2
  exit 1
fi

REQUIREMENTS=("git" "java")
for i in "${REQUIREMENTS[@]}"; do
  if ! command -v "${i}" &> /dev/null; then
    echo "'${i}' is required to run this script. Please install it." >&2
    exit 1
  fi
done

RATCHET_REF="${PRE_COMMIT_FROM_REF:-HEAD^}"
echo "Running spotlessApply on files changed since ${RATCHET_REF}"

# shellcheck source=../gradlew
./gradlew --no-daemon --console=plain :spotlessApply -PratchetFrom="${RATCHET_REF}"
