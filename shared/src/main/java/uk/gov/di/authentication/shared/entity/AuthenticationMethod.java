package uk.gov.di.authentication.shared.entity;

public enum AuthenticationMethod {
    EMAIL("EMAIL"),
    PASSWORD("PASSWORD"),
    AUTH_APP("AUTH_APP"),
    SMS("SMS");

    private String value;

    AuthenticationMethod(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
