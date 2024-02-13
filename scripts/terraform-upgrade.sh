#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"

TMPDIR=${TMPDIR:-/tmp}
TF_DATA_DIR_BASE=$(mktemp -d "${TMPDIR}/terraform_lint.XXXXXX")
trap 'rm -r "${TF_DATA_DIR_BASE}"' EXIT

for dir in "${repo_root}"/ci/terraform/*; do
    test ! -d "${dir}" && continue

    dir_name="${dir##*/}"
    export TF_DATA_DIR="${TF_DATA_DIR_BASE}/${dir_name}"

    printf "Upgrading providers for \e[1;93m%s\e[0m...\n" "${dir_name}"

    printf "\e[92m*\e[0m Initializing..."
    terraform -chdir="${dir}" init -backend=false -upgrade &>/dev/null
    printf " done!\n"

    printf "\e[92m*\e[0m Locking provider versions:\n"
    terraform -chdir="${dir}" providers lock \
        -platform=windows_amd64 \
        -platform=linux_amd64 \
        -platform=linux_arm64 \
        -platform=darwin_amd64 \
        -platform=darwin_arm64
    unset TF_DATA_DIR
done
