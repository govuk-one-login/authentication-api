package uk.gov.di.orchestration.shared.entity;

public enum PublicKeySource {
    STATIC("STATIC"),
    JWKS("JWKS");

    private String value;

    PublicKeySource(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
