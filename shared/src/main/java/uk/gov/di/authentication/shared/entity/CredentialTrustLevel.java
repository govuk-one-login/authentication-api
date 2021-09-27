package uk.gov.di.authentication.shared.entity;

public enum CredentialTrustLevel {
    LOW_LEVEL("Cl"),
    MEDIUM_LEVEL("Cm"),
    HIGH_LEVEL("Ch"),
    VERY_HIGH_LEVEL("Cv");

    private String value;

    CredentialTrustLevel(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
