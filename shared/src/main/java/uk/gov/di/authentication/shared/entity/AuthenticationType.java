package uk.gov.di.authentication.shared.entity;

public enum AuthenticationType {
    EMAIL("EMAIL"),
    PASSWORD("PASSWORD"),
    AUTH_APP("AUTH_APP"),
    SMS("SMS");

    private String value;

    AuthenticationType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
