#!/usr/bin/env bash

set -euo pipefail

FORCE="${FORCE:-false}"

name="${1}"
incoming_value="${2:-}"
value=""

if [[ ${name} =~ ^[a-zA-Z0-9_]+= ]]; then
    name="${1%=*}"
    value="${1#*=}"
fi
if [[ ${name} =~ [^a-zA-Z0-9_] ]]; then
    printf '\e[31m!\e[0m Secret name must match /^[a-zA-Z0-9_]$/'
    exit 1
fi

if [ -n "${incoming_value}" ]; then
    value="${incoming_value}"
fi

[ -z "${value}" ] && read -rp "Enter value for ${name}: " value

secret_name="/deploy/sandpit/${name}"

printf '\e[36m*\e[0m Secret Name: "\e[33m%s\e[0m", Value: "\e[36m%s\e[0m"\n\n' "${secret_name}" "${value}"

if [[ "${FORCE}" != "true" ]]; then
    read -r -p "Press enter to continue, Ctrl+C to abort..."
fi

verb="created"

create="$(aws secretsmanager create-secret \
    --name "${secret_name}" \
    --description "${name}" \
    --secret-string "${value}" \
    --region eu-west-2 \
    --tags '[{"Key": "Name", "Value": "'"${name}"'"}, {"Key": "Environment", "Value": "sandpit"}]' 2>&1)" ||
    {
        if [[ ${create} =~ 'already exists.'$ ]]; then
            verb="updated"
        else
            printf '\e[31m!\e[0m Failed to create secret "%s"\n%s' "${secret_name}" "${create}"
            exit 1
        fi
    }

if [[ "${verb}" == "updated" ]]; then
    secret_arn="$(aws secretsmanager list-secrets \
        --filter "Key=\"name\",Values=\"${secret_name}\"" --region eu-west-2 |
        jq -r '.SecretList[0].ARN')"
    if [ -z "${secret_arn}" ]; then
        exit 1
    fi
    existing_value="$(aws secretsmanager get-secret-value \
        --secret-id "${secret_arn}" --region eu-west-2 |
        jq -r '.SecretString')"

    printf '\e[36m*\e[0m Secret "\e[33m%s\e[0m" already exists with value "\e[36m%s\e[0m". Updating it with the provided value.\n' "${secret_name}" "${existing_value}"

    update="$(aws secretsmanager update-secret \
        --secret-id "${secret_arn}" \
        --description "${name}" \
        --secret-string "${value}" \
        --region eu-west-2 2>&1)" ||
        {
            printf '\e[31m!\e[0m Failed to update secret "%s"\n%s' "${secret_name}" "${update}"
            exit 1
        }
    printf '\e[36m*\e[0m Updated secret value\n'

    tag="$(aws secretsmanager tag-resource \
        --secret-id "${secret_arn}" \
        --tags '[{"Key": "Name", "Value": "'"${name}"'"}, {"Key": "Environment", "Value": "sandpit"}]' 2>&1)" ||
        {
            printf '\e[31m!\e[0m Failed to tag secret "%s"\n%s' "${secret_name}" "${tag}"
            exit 1
        }
    printf '\e[36m*\e[0m Updated secret tags\n'
fi

printf '\e[32m✓\e[0m Secret "\e[33m%s\e[0m" %s successfully\n' "${secret_name}" "${verb}"
