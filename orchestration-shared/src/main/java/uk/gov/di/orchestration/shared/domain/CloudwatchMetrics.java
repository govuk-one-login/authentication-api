package uk.gov.di.orchestration.shared.domain;

public enum CloudwatchMetrics {
    AUTHENTICATION_SUCCESS("AuthenticationSuccess"),
    AUTHENTICATION_SUCCESS_NEW_ACCOUNT_BY_CLIENT("AuthenticationSuccessNewAccountByClient"),
    AUTHENTICATION_SUCCESS_EXISTING_ACCOUNT_BY_CLIENT(
            "AuthenticationSuccessExistingAccountByClient"),
    LOGOUT_SUCCESS("LogoutSuccess"),
    SIGN_IN_NEW_ACCOUNT_BY_CLIENT("SignInNewAccountByClient"),
    SIGN_IN_EXISTING_ACCOUNT_BY_CLIENT("SignInExistingAccountByClient"),
    SUCCESSFUL_TOKEN_ISSUED("SuccessfulTokenIssued"),
    USER_INFO_RETURNED("UserInfoReturned"),
    AUTH_TOKEN_REQUEST_SUCCESSFUL("AuthTokenRequestSuccessful"),
    AUTH_TOKEN_REQUEST_FAILED("AuthTokenRequestFailed"),
    AUTH_USER_INFO_REQUEST_SUCCESSFUL("AuthUserInfoRequestSuccessful"),
    AUTH_USER_INFO_REQUEST_FAILED("AuthUserInfoRequestFailed"),
    IPV_TOKEN_REQUEST_SUCCESSFUL("IpvTokenRequestSuccessful"),
    IPV_TOKEN_REQUEST_FAILED("IpvTokenRequestFailed"),
    IPV_USER_INFO_REQUEST_SUCCESSFUL("IpvUserInfoRequestSuccessful"),
    IPV_USER_INFO_REQUEST_FAILED("IpvUserInfoRequestFailed"),
    DOC_APP_TOKEN_REQUEST_SUCCESSFUL("DocAppTokenRequestSuccessful"),
    DOC_APP_TOKEN_REQUEST_FAILED("DocAppTokenRequestFailed"),
    DOC_APP_USER_INFO_REQUEST_SUCCESSFUL("DocAppUserInfoRequestSuccessful"),
    DOC_APP_USER_INFO_REQUEST_FAILED("DocAppUserInfoRequestFailed");
    private String value;

    CloudwatchMetrics(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
