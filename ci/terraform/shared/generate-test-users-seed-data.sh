#!/bin/bash
echo "Creating vars files"
mkdir test-users-seed-data
touch test-users-seed-data/test-users.vars

echo "Getting environment variables from SSM ... "

SSM_VARS_PATH="/acceptance-tests/dev"
VARS="$(aws ssm get-parameters-by-path --region eu-west-2 --with-decryption --path $SSM_VARS_PATH | jq -r '.Parameters[] | @base64')"
TERMS_AND_CONDITIONS_VERSION="1.0"

for VAR in $VARS; do
  VAR_NAME="$(echo ${VAR} | base64 -d | jq -r '.Name / "/" | .[3]')"
  VAR_NAME_VALUE=$VAR_NAME="$(echo ${VAR} | base64 -d | jq -r '.Value')"
  export "$VAR_NAME"="$(echo ${VAR} | base64 -d | jq -r '.Value')"
done
echo "Exported SSM parameters completed."

echo "Generating test user seed data..."
HASHED_PASSWORD=$(echo -n "${TERMS_AND_CONDITIONS_TEST_USER_PASSWORD}" | argon2 $(openssl rand -hex 32) -e -id -v 13 -k 15360 -t 2 -p 1)
HASHED_PASSWORD_RESEND=$(echo -n "${RESEND_CODE_TEST_USER_PASSWORD}" | argon2 $(openssl rand -hex 32) -e -id -v 13 -k 15360 -t 2 -p 1)
HASHED_PASSWORD_IPN4=$(echo -n "${IPN4_EXISTING_USER_PASSWORD}" | argon2 $(openssl rand -hex 32) -e -id -v 13 -k 15360 -t 2 -p 1)
HASHED_PASSWORD_RESET=$(echo -n "${RESET_PW_CURRENT_PW}" | argon2 $(openssl rand -hex 32) -e -id -v 13 -k 15360 -t 2 -p 1)
HASHED_PASSWORD_REQ_RESET=$(echo -n "${REQ_RESET_PW_CURRENT_PW}" | argon2 $(openssl rand -hex 32) -e -id -v 13 -k 15360 -t 2 -p 1)
HASHED_PASSWORD_PW_RESET=$(echo -n "${PW_RESET_TEST_USER_PASSWORD}" | argon2 $(openssl rand -hex 32) -e -id -v 13 -k 15360 -t 2 -p 1)
cat <<EOF > test-users-seed-data/test-users.vars
[
  {
      username = "$TERMS_AND_CONDITIONS_TEST_USER_EMAIL"
      hashed_password = "$HASHED_PASSWORD"
      phone = "$TERMS_AND_CONDITIONS_TEST_USER_PHONE"
      terms_and_conditions_version = "$TERMS_AND_CONDITIONS_VERSION"
      auth_app_secret = ""
  },
  {
      username = "$RESEND_CODE_TEST_USER_EMAIL"
      hashed_password = "$HASHED_PASSWORD_RESEND"
      phone = "$RESEND_CODE_TEST_USER_PHONE"
      terms_and_conditions_version = "$TEST_USER_LATEST_TERMS_AND_CONDITIONS_VERSION"
      auth_app_secret = ""
  },
  {
      username = "$IPN4_EXISTING_USER_EMAIL"
      hashed_password = "$HASHED_PASSWORD_IPN4"
      phone = "$IPN4_EXISTING_USER_PHONE"
      terms_and_conditions_version = "$TEST_USER_LATEST_TERMS_AND_CONDITIONS_VERSION"
      auth_app_secret = ""
  },
  {
      username = "$RESET_PW_USER_EMAIL"
      hashed_password = "$HASHED_PASSWORD_RESET"
      phone = "$RESET_PW_USER_PHONE"
      terms_and_conditions_version = "$TEST_USER_LATEST_TERMS_AND_CONDITIONS_VERSION"
      auth_app_secret = ""
  },
  {
      username = "$REQ_RESET_PW_USER_EMAIL"
      hashed_password = "$HASHED_PASSWORD_REQ_RESET"
      phone = "$RESET_PW_USER_PHONE"
      terms_and_conditions_version = "$TEST_USER_LATEST_TERMS_AND_CONDITIONS_VERSION"
      auth_app_secret = ""
  },
  {
      username = "$TEST_USER_ACCOUNT_RECOVERY_EMAIL_1"
      hashed_password = "$HASHED_PASSWORD_PW_RESET"
      phone = "$PW_RESET_TEST_USER_PHONE"
      terms_and_conditions_version = "$TEST_USER_LATEST_TERMS_AND_CONDITIONS_VERSION"
      auth_app_secret = ""
  },
  {
      username = "$TEST_USER_ACCOUNT_RECOVERY_EMAIL_2"
      hashed_password = "$HASHED_PASSWORD_PW_RESET"
      phone = "$PW_RESET_TEST_USER_PHONE"
      terms_and_conditions_version = "$TEST_USER_LATEST_TERMS_AND_CONDITIONS_VERSION"
      auth_app_secret = "$ACCOUNT_RECOVERY_USER_AUTH_APP_SECRET"
  },
  {
      username = "$TEST_USER_ACCOUNT_RECOVERY_EMAIL_3"
      hashed_password = "$HASHED_PASSWORD_PW_RESET"
      phone = "$PW_RESET_TEST_USER_PHONE"
      terms_and_conditions_version = "$TEST_USER_LATEST_TERMS_AND_CONDITIONS_VERSION"
      auth_app_secret = ""
  },
  {
      username = "$TEST_USER_ACCOUNT_RECOVERY_EMAIL_4"
      hashed_password = "$HASHED_PASSWORD_PW_RESET"
      phone = "$PW_RESET_TEST_USER_PHONE"
      terms_and_conditions_version = "$TEST_USER_LATEST_TERMS_AND_CONDITIONS_VERSION"
      auth_app_secret = "$ACCOUNT_RECOVERY_USER_AUTH_APP_SECRET"
  }
]
EOF

echo "Exporting seed data as TF_VAR_"
TEST_USERS=$(cat test-users-seed-data/test-users.vars)
export TF_VAR_test_users=$TEST_USERS