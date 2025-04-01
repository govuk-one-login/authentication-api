#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

find "${DIR}/../ci" -type f -name "read_secrets.sh" -exec cp "${DIR}/read_secrets__main.sh" {} \;
find "${DIR}/../ci" -type f -name "secrets-to-tfvars.py" -exec cp "${DIR}/secrets-to-tfvars.py" {} \;
