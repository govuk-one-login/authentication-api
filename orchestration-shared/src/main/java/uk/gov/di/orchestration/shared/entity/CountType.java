package uk.gov.di.orchestration.shared.entity;

public enum CountType {
    ENTER_PASSWORD("ENTER_PASSWORD"),
    ENTER_SMS_CODE("ENTER_SMS_CODE"),
    ENTER_AUTH_APP_CODE("ENTER_AUTH_APP_CODE"),
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
