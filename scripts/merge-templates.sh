#!/usr/bin/env bash
set -euo pipefail

node scripts/cfn-merge/merge-templates.js \
  "${GITHUB_WORKSPACE}/${TEMPLATE_SOURCE_DIR}" \
  "${TEMPLATE_FILE}"
