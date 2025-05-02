#!/usr/bin/env bash

STATE_OUT="build-shared-terraform.tfstate"
STATE_IN="frontend-build-terraform.tfstate"

function migrate() {
  terraform state mv -state "${STATE_IN}" -state-out "${STATE_OUT}" "$1" "$2"
}

## KMS

migrate aws_kms_key.authentication_encryption_key aws_kms_key.authentication_encryption_key
migrate aws_kms_key_policy.authentication_encryption_key_access_policy aws_kms_key_policy.authentication_encryption_key_access_policy
migrate aws_kms_alias.authentication_encryption_key_alias aws_kms_alias.authentication_encryption_key_alias

## Random password
migrate random_password.redis_password random_password.frontend_redis_password

## SSM redis
migrate aws_kms_key.parameter_store_key aws_kms_key.frontend_parameter_store_key
migrate aws_kms_alias.parameter_store_key_alias aws_kms_alias.frontend_parameter_store_key_alias
migrate aws_ssm_parameter.redis_master_host aws_ssm_parameter.frontend_redis_master_host
migrate aws_ssm_parameter.redis_replica_host aws_ssm_parameter.frontend_redis_replica_host
migrate aws_ssm_parameter.redis_tls aws_ssm_parameter.frontend_redis_tls
migrate aws_ssm_parameter.redis_password aws_ssm_parameter.frontend_redis_password
migrate aws_ssm_parameter.redis_port aws_ssm_parameter.frontend_redis_port
migrate aws_iam_policy.parameter_policy aws_iam_policy.frontend_parameter_policy
