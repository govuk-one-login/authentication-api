#!/usr/bin/env bash
set -euo pipefail

if ! command -v tflint &>/dev/null; then
    # shellcheck disable=SC2016
    echo 'tflint is not installed. Please install tflint with `brew install tflint`.'
    exit 1
fi

# Run `tflint --init` to check that plugins are installed.
# It should run once on whole repo.
{
    TFLINT_INIT=$(tflint --init "${ARGS[@]}" 2>&1) 2>/dev/null &&
        echo "Command 'tflint --init' successfully done:" &&
        echo -e "${TFLINT_INIT}\n\n\n"
} || {
    exit_code=$?
    echo "Command 'tflint --init' failed:"
    echo -e "${TFLINT_INIT}"
    return ${exit_code}
}

files=("${@}")

directories=()
for file in "${files[@]}"; do
    dirname=$(dirname "$file")
    directories+=("$dirname")
done

mapfile -t unique_directories < <(printf "%s\n" "${directories[@]}" | sort -u)

errorred=false
for directory in "${unique_directories[@]}"; do
    if ! tflint --fix --module --chdir "${directory}"; then
        errorred=true
    fi
done

if [ "$errorred" = true ]; then
    exit 1
fi
