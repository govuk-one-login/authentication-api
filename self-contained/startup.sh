#!/usr/bin/env sh
set -eu

sh /usr/local/bin/dockerd-entrypoint.sh &> dockerd-logfile &
sleep 5
tail dockerd-logfile
ls
docker compose -f docker-compose.yml up

DEPLOY_ENV=localstack

runTerraform() {
    echo "Running ${1} Terraform..."
    cd "ci/terraform/${1}"
    rm -rf .terraform/
    terraform init -backend-config="${DEPLOY_ENV}".hcl
#    terraform apply -var-file "${DEPLOY_ENV}".tfvars
    cd -
}

runTerraform "shared"
#runTerraform "oidc"
#runTerraform "interventions-api-stub"
#runTerraform "ticf-cri-stub"
#runTerraform "account-management"
#runTerraform "audit"
#runTerraform "delivery-receipts"
#runTerraform "utils"
#runTerraform "test-services"
#runTerraform "auth-external-api"