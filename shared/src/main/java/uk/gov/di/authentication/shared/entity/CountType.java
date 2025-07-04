package uk.gov.di.authentication.shared.entity;

public enum CountType {
    ENTER_PASSWORD("ENTER_PASSWORD"),
    ENTER_MFA_CODE("ENTER_MFA_CODE"),
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
