package uk.gov.di.authentication.shared.entity;

public enum PriorityIdentifier {
    PRIMARY("PRIMARY"),
    SECONDARY("SECONDARY");

    private String value;

    PriorityIdentifier(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
