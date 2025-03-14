package uk.gov.di.authentication.shared.entity.mfa;

public enum MFAMethodType {
    EMAIL("EMAIL"),
    AUTH_APP("AUTH_APP"),
    SMS("SMS"),
    NONE("NONE");

    private String value;

    MFAMethodType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
