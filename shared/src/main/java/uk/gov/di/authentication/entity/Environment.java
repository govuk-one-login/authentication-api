package uk.gov.di.authentication.entity;

public enum Environment {
    PRODUCTION("production"),
    INTEGRATION("integration");

    private final String value;

    Environment(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
