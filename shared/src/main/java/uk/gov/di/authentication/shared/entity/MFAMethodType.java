package uk.gov.di.authentication.shared.entity;

public enum MFAMethodType {
    EMAIL("EMAIL"),
    AUTH_APP("AUTH_APP"),
    SMS("SMS");

    private String value;

    MFAMethodType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
