package uk.gov.di.authentication.shared.entity;

public enum EmailCheckResultStatus {
    PENDING("PENDING"),
    ALLOW("ALLOW"),
    DENY("DENY");

    private String value;

    EmailCheckResultStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
