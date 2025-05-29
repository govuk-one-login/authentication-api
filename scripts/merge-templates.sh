#!/usr/bin/env bash
set -euo pipefail

if ! command -v rain &> /dev/null; then
  echo "Merging templates requires rain to be installed. See https://github.com/aws-cloudformation/rain for installation instructions."
  exit 1
fi

# shellcheck disable=SC2046
rain merge $(find "${GITHUB_WORKSPACE}/${TEMPLATE_SOURCE_DIR}" -type f \( -name "*.yaml" -o -name "*.yml" \) -print) -o "${TEMPLATE_FILE}"
