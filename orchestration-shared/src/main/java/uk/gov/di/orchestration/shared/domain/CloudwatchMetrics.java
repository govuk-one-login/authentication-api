package uk.gov.di.orchestration.shared.domain;

public enum CloudwatchMetrics {
    AUTHENTICATION_SUCCESS("AuthenticationSuccess"),
    AUTHENTICATION_SUCCESS_NEW_ACCOUNT_BY_CLIENT("AuthenticationSuccessNewAccountByClient"),
    AUTHENTICATION_SUCCESS_EXISTING_ACCOUNT_BY_CLIENT(
            "AuthenticationSuccessExistingAccountByClient"),
    SIGN_IN_NEW_ACCOUNT_BY_CLIENT("SignInNewAccountByClient"),
    SIGN_IN_EXISTING_ACCOUNT_BY_CLIENT("SignInExistingAccountByClient"),
    LOGOUT_SUCCESS("LogoutSuccess");
    private String value;

    CloudwatchMetrics(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
