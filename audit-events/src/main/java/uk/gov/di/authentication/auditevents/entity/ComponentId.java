package uk.gov.di.authentication.auditevents.entity;

public enum ComponentId {
    AUTH("AUTH");

    private final String value;

    ComponentId(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
