package uk.gov.di.authentication.shared.entity;

public enum CountType {
    ENTER_PASSWORD("ENTER_PASSWORD"),
    ENTER_MFA_CODE("ENTER_MFA_CODE"),
    // TODO START remove temporary ZDD measure to keep deprecated count types
    ENTER_SMS_CODE("ENTER_SMS_CODE"),
    ENTER_AUTH_APP_CODE("ENTER_AUTH_APP_CODE"),
    // TODO END remove temporary ZDD measure to keep deprecated count types
    ENTER_EMAIL_CODE("ENTER_EMAIL_CODE"),
    ENTER_EMAIL("ENTER_EMAIL");

    private String value;

    CountType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
