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
    MFA_RESET_HANDOFF("MfaResetHandoff");
    private String value;

    CloudwatchMetrics(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
