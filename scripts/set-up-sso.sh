#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# test if a python virtualenv already exists
if [ -d "${DIR}/.venv" ]; then
    echo "! Using existing virtualenv"
else
    echo "C! reating virtualenv"
    python3 -m venv "${DIR}/.venv"
fi

# activate the virtualenv
# shellcheck source=/dev/null
source "${DIR}/.venv/bin/activate"

# install dependencies
echo "! installing python dependencies"
pip3 install -r "${DIR}/requirements.txt"

echo
echo

python3 "${DIR}/_set-up-sso.py"
