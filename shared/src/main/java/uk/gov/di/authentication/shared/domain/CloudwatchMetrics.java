package uk.gov.di.authentication.shared.domain;

public enum CloudwatchMetrics {
    AUTHENTICATION_SUCCESS("AuthenticationSuccess"),
    AUTHENTICATION_SUCCESS_NEW_ACCOUNT_BY_CLIENT("AuthenticationSuccessNewAccountByClient"),
    AUTHENTICATION_SUCCESS_EXISTING_ACCOUNT_BY_CLIENT(
            "AuthenticationSuccessExistingAccountByClient"),
    SIGN_IN_NEW_ACCOUNT_BY_CLIENT("SignInNewAccountByClient"),
    SIGN_IN_EXISTING_ACCOUNT_BY_CLIENT("SignInExistingAccountByClient"),
    LOGOUT_SUCCESS("LogoutSuccess"),
    EMAIL_CHECK_DURATION("EmailCheckDuration"),
    REAUTH_REQUESTED("ReauthRequested"),
    REAUTH_FAILED("ReauthFailed"),
    REAUTH_SUCCESS("ReauthSuccess"),
    MFA_RESET_HANDOFF("MfaResetHandoff"),
    ACCESS_TOKEN_SERVICE_INITIAL_QUERY_ATTEMPT("AccessTokenServiceInitialQueryAttempt"),
    ACCESS_TOKEN_SERVICE_INITIAL_QUERY_SUCCESS("AccessTokenServiceInitialQuerySuccess"),
    ACCESS_TOKEN_SERVICE_CONSISTENT_READ_QUERY_ATTEMPT(
            "AccessTokenServiceConsistentReadQueryAttempt"),
    ACCESS_TOKEN_SERVICE_CONSISTENT_READ_QUERY_SUCCESS(
            "AccessTokenServiceConsistentReadQueryAttemptSuccess"),
    USER_SUBMITTED_CREDENTIAL("UserSubmittedCredential"),
    MFA_RESET_IPV_RESPONSE("MfaResetIpvResponse"),
    MFA_RESET_AUTHORISATION_ERROR("ReverifyAuthorisationError"),
    SMS_NOTIFICATION_SENT("SmsNotificationSent"),
    EMAIL_NOTIFICATION_SENT("EmailNotificationSent"),
    SMS_NOTIFICATION_ERROR("SmsNotificationError"),
    EMAIL_NOTIFICATION_ERROR("EmailNotificationError"),
    SMS_LIMIT_EXCEEDED("SmsLimitExceeded");

    private String value;

    CloudwatchMetrics(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
