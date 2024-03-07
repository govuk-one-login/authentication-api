#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# Ensure python is at least 3.10
min_python_version=3.10
python_version="$(python3 --version | cut -d' ' -f2)"
if [ "$(printf '%s\n' "${min_python_version}" "${python_version}" | sort -V | head -n1)" != "${min_python_version}" ]; then
    # shellcheck disable=SC2016
    printf 'Please install python %s or later (found: %s). You could probably use `brew install python@3.12`' "${min_python_version}" "${python_version}"
    exit 1
fi

# test if a python virtualenv already exists
if [ -d "${DIR}/.venv" ]; then
    echo "! Using existing virtualenv"
else
    echo "! Creating virtualenv"
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

FROM_WRAPPER=true python3 "${DIR}/_set-up-sso.py"
