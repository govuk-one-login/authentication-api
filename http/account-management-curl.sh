#!/bin/bash

# Account Management API curl scripts
# Please read guidance on confluence before use
# (https://govukverify.atlassian.net/wiki/spaces/LO/pages/4606132332/Manually+Testing+Account+Management+API).
# Populate the variables below (use scripts/generate-auth-token.sh for authToken)

# Variables - UPDATE THESE BEFORE RUNNING
BASE_URL="https://your-api-endpoint.com"
AUTH_TOKEN="your-auth-token-here"
EMAIL="your.email@digital.cabinet-office.gov.uk"
PUBLIC_SUBJECT_ID="your-public-subject-id"
MFA_IDENTIFIER="your-mfa-identifier"

# Function to check if variables are set
check_variables() {
    if [[ "$AUTH_TOKEN" == "your-auth-token-here" ]]; then
        echo "Error: Please set AUTH_TOKEN variable"
        exit 1
    fi
    if [[ "$BASE_URL" == "https://your-api-endpoint.com" ]]; then
        echo "Error: Please set BASE_URL variable"
        exit 1
    fi
    if [[ "$EMAIL" == "your.email@digital.cabinet-office.gov.uk" ]]; then
        echo "Error: Please set EMAIL variable"
        exit 1
    fi
}

# Authenticate
authenticate() {
    local password=${2:-"currentPassword123!"}
    echo "=== POST /authenticate ==="
    echo "curl -X POST \"$BASE_URL/authenticate\" \\"
    echo "    -H \"Authorization: Bearer $AUTH_TOKEN\" \\"
    echo "    -H \"Content-Type: application/json\" \\"
    echo "    -d '{"
    echo "        \"email\": \"$EMAIL\","
    echo "        \"password\": \"$password\""
    echo "    }'"
    echo ""
    curl -X POST "$BASE_URL/authenticate" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "email": "'$EMAIL'",
            "password": "'$password'"
        }'
    echo -e "\n"
}

# Send OTP notification
send_otp_notification() {
    local notification_type=${1:-"VERIFY_EMAIL"}
    echo "=== POST /send-otp-notification ==="
    curl -X POST "$BASE_URL/send-otp-notification" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "notificationType": "'$notification_type'",
            "email": "'$EMAIL'",
            "phoneNumber": "07xxxxxxxxx"
        }'
    echo -e "\n"
}

# Update email (REQUIRES CLIENT REGISTRY CHANGE)
update_email() {
    echo "=== POST /update-email ==="
    echo "WARNING: REQUIRES CLIENT REGISTRY CHANGE - CHANGE BACK AFTER USE"
    curl -X POST "$BASE_URL/update-email" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "existingEmailAddress": "'$EMAIL'",
            "replacementEmailAddress": "new_email_registered.with_notify@digital.cabinet-office.gov.uk",
            "otp": "111111"
        }'
    echo -e "\n"
}

# Delete account (REQUIRES CLIENT REGISTRY CHANGE)
delete_account() {
    echo "=== POST /delete-account ==="
    echo "WARNING: REQUIRES CLIENT REGISTRY CHANGE - CHANGE BACK AFTER USE"
    curl -X POST "$BASE_URL/delete-account" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "email": "'$EMAIL'"
        }'
    echo -e "\n"
}

# Update password (REQUIRES CLIENT REGISTRY CHANGE)
update_password() {
    local new_password=${2:-"newPassword123!"}
    echo "=== POST /update-password ==="
    echo "WARNING: REQUIRES CLIENT REGISTRY CHANGE - CHANGE BACK AFTER USE"
    curl -X POST "$BASE_URL/update-password" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "email": "'$EMAIL'",
            "newPassword": "'$new_password'"
        }'
    echo -e "\n"
}

# Update phone number (REQUIRES CLIENT REGISTRY CHANGE)
update_phone_number() {
    echo "=== POST /update-phone-number ==="
    echo "WARNING: REQUIRES CLIENT REGISTRY CHANGE - CHANGE BACK AFTER USE"
    curl -X POST "$BASE_URL/update-phone-number" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "email": "'$EMAIL'",
            "phoneNumber": "07xxxxxxxxx",
            "otp": "111111"
        }'
    echo -e "\n"
}

# Get MFA methods
get_mfa_methods() {
    if [[ "$PUBLIC_SUBJECT_ID" == "your-public-subject-id" ]]; then
        echo "Error: Please set PUBLIC_SUBJECT_ID variable"
        return 1
    fi
    echo "=== GET /v1/mfa-methods/$PUBLIC_SUBJECT_ID ==="
    curl -X GET "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID" \
        -H "Authorization: Bearer $AUTH_TOKEN"
    echo -e "\n"
}

# Create SMS MFA method
create_sms_mfa() {
    if [[ "$PUBLIC_SUBJECT_ID" == "your-public-subject-id" ]]; then
        echo "Error: Please set PUBLIC_SUBJECT_ID variable"
        return 1
    fi
    echo "=== POST /v1/mfa-methods/$PUBLIC_SUBJECT_ID (SMS) ==="
    curl -X POST "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "mfaMethod": {
                "priorityIdentifier": "BACKUP",
                "method": {
                    "mfaMethodType": "SMS",
                    "phoneNumber": "07xxxxxxxxx",
                    "otp": "111111"
                }
            }
        }'
    echo -e "\n"
}

# Create Auth App MFA method
create_auth_app_mfa() {
    if [[ "$PUBLIC_SUBJECT_ID" == "your-public-subject-id" ]]; then
        echo "Error: Please set PUBLIC_SUBJECT_ID variable"
        return 1
    fi
    echo "=== POST /v1/mfa-methods/$PUBLIC_SUBJECT_ID (Auth App) ==="
    curl -X POST "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "mfaMethod": {
                "priorityIdentifier": "BACKUP",
                "method": {
                    "mfaMethodType": "AUTH_APP",
                    "credential": "your-credential-here"
                }
            }
        }'
    echo -e "\n"
}

# Delete MFA method
delete_mfa_method() {
    if [[ "$PUBLIC_SUBJECT_ID" == "your-public-subject-id" ]]; then
        echo "Error: Please set PUBLIC_SUBJECT_ID variable"
        return 1
    fi
    if [[ "$MFA_IDENTIFIER" == "your-mfa-identifier" ]]; then
        echo "Error: Please set MFA_IDENTIFIER variable"
        return 1
    fi
    echo "=== DELETE /v1/mfa-methods/$PUBLIC_SUBJECT_ID/$MFA_IDENTIFIER ==="
    curl -X DELETE "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID/$MFA_IDENTIFIER" \
        -H "Authorization: Bearer $AUTH_TOKEN"
    echo -e "\n"
}

# Update SMS MFA method
update_sms_mfa() {
    if [[ "$PUBLIC_SUBJECT_ID" == "your-public-subject-id" ]]; then
        echo "Error: Please set PUBLIC_SUBJECT_ID variable"
        return 1
    fi
    if [[ "$MFA_IDENTIFIER" == "your-mfa-identifier" ]]; then
        echo "Error: Please set MFA_IDENTIFIER variable"
        return 1
    fi
    echo "=== PUT /v1/mfa-methods/$PUBLIC_SUBJECT_ID/$MFA_IDENTIFIER (SMS) ==="
    curl -X PUT "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID/$MFA_IDENTIFIER" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "mfaMethod": {
                "priorityIdentifier": "BACKUP",
                "method": {
                    "mfaMethodType": "SMS",
                    "phoneNumber": "07xxxxxxxxx",
                    "otp": "111111"
                }
            }
        }'
    echo -e "\n"
}

# Update Auth App MFA method
update_auth_app_mfa() {
    if [[ "$PUBLIC_SUBJECT_ID" == "your-public-subject-id" ]]; then
        echo "Error: Please set PUBLIC_SUBJECT_ID variable"
        return 1
    fi
    if [[ "$MFA_IDENTIFIER" == "your-mfa-identifier" ]]; then
        echo "Error: Please set MFA_IDENTIFIER variable"
        return 1
    fi
    echo "=== PUT /v1/mfa-methods/$PUBLIC_SUBJECT_ID/$MFA_IDENTIFIER (Auth App) ==="
    curl -X PUT "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID/$MFA_IDENTIFIER" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "mfaMethod": {
                "priorityIdentifier": "BACKUP",
                "method": {
                    "mfaMethodType": "AUTH_APP",
                    "credential": "your-credential-here"
                }
            }
        }'
    echo -e "\n"
}

# Help function
show_help() {
    echo "Account Management API curl scripts"
    echo ""
    echo "Usage: $0 [function_name]"
    echo ""
    echo "Available functions:"
    echo "  authenticate [password]   - POST /authenticate"
    echo "  send_otp_notification     - POST /send-otp-notification"
    echo "  update_email              - POST /update-email (requires client registry change)"
    echo "  delete_account            - POST /delete-account (requires client registry change)"
    echo "  update_password [password] - POST /update-password (requires client registry change)"
    echo "  update_phone_number       - POST /update-phone-number (requires client registry change)"
    echo "  get_mfa_methods           - GET /v1/mfa-methods/{publicSubjectId}"
    echo "  create_sms_mfa            - POST /v1/mfa-methods/{publicSubjectId} (SMS)"
    echo "  create_auth_app_mfa       - POST /v1/mfa-methods/{publicSubjectId} (Auth App)"
    echo "  delete_mfa_method         - DELETE /v1/mfa-methods/{publicSubjectId}/{mfaIdentifier}"
    echo "  update_sms_mfa            - PUT /v1/mfa-methods/{publicSubjectId}/{mfaIdentifier} (SMS)"
    echo "  update_auth_app_mfa       - PUT /v1/mfa-methods/{publicSubjectId}/{mfaIdentifier} (Auth App)"
    echo ""
    echo "Before running, update the variables at the top of this script:"
    echo "  - BASE_URL"
    echo "  - AUTH_TOKEN (use scripts/generate-auth-token.sh)"
    echo "  - PUBLIC_SUBJECT_ID (for MFA endpoints)"
    echo "  - MFA_IDENTIFIER (for specific MFA operations)"
}

# Main execution
if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

case "$1" in
    authenticate)
        check_variables
        authenticate "$2"
        ;;
    send_otp_notification)
        check_variables
        send_otp_notification "$2"
        ;;
    update_email)
        check_variables
        update_email
        ;;
    delete_account)
        check_variables
        delete_account
        ;;
    update_password)
        check_variables
        update_password "$2"
        ;;
    update_phone_number)
        check_variables
        update_phone_number
        ;;
    get_mfa_methods)
        check_variables
        get_mfa_methods
        ;;
    create_sms_mfa)
        check_variables
        create_sms_mfa
        ;;
    create_auth_app_mfa)
        check_variables
        create_auth_app_mfa
        ;;
    delete_mfa_method)
        check_variables
        delete_mfa_method
        ;;
    update_sms_mfa)
        check_variables
        update_sms_mfa
        ;;
    update_auth_app_mfa)
        check_variables
        update_auth_app_mfa
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown function: $1"
        echo "Run '$0 help' for available functions"
        exit 1
        ;;
esac