package uk.gov.di.authentication.frontendapi.entity;

public enum ReauthFailureReasons {
    INCORRECT_EMAIL("incorrect_email"),
    INCORRECT_PASSWORD("incorrect_password"),
    INCORRECT_OTP("incorrect_otp"),
    UNKNOWN("unknown");

    private final String value;

    ReauthFailureReasons(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
