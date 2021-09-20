package uk.gov.di.authentication.shared.entity;

public enum AuthenticationValues {
    LOW_LEVEL("Cl"),
    MEDIUM_LEVEL("Cm"),
    HIGH_LEVEL("Ch"),
    VERY_HIGH_LEVEL("Cv");

    private String value;

    AuthenticationValues(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
