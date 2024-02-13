#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"

TMPDIR=${TMPDIR:-/tmp}
TF_DATA_DIR_BASE=$(mktemp -d "${TMPDIR}/terraform_lint.XXXXXX")
trap 'rm -r "${TF_DATA_DIR_BASE}"' EXIT

specific_dir="${1:-}"

function lint_module() {
    local module_dir="${1}"
    local module_name
    module_name="$(basename "${module_dir}")"
    export TF_DATA_DIR="${TF_DATA_DIR_BASE}/${module_name}"

    printf "Validating \e[1;93m%s\e[0m...\n" "${module_name}"
    printf "\e[92m*\e[0m Initializing..."
    terraform -chdir="${module_dir}" init -backend=false &>/dev/null
    printf " done!\n"

    terraform -chdir="${module_dir}" validate
    terraform -chdir="${module_dir}" fmt -write=false -diff -recursive >>"${TF_DATA_DIR}"/lint
    if [ -s "${TF_DATA_DIR}"/lint ]; then
        printf "\e[1;91m%s\e[0m\n" "The following files need to be formatted:"
        cat "${TF_DATA_DIR}"/lint
    else
        printf "\e[92m*\e[0m No formatting issues found.\n"
    fi
    unset TF_DATA_DIR
}

if [[ -n "${specific_dir}" ]]; then
    printf "Linting directory \e[1;93m%s\e[0m.\n" "${specific_dir}"
    test ! -d "${specific_dir}" && printf "Directory \e[1;93m%s\e[0m does not exist.\n" "${specific_dir}" && exit 1
    lint_module "${specific_dir}"
else
    for dir in "${repo_root}"/ci/terraform/*; do
        test ! -d "${dir}" && continue
        lint_module "${dir}"
    done
fi
