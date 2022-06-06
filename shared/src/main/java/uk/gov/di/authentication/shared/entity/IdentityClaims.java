package uk.gov.di.authentication.shared.entity;

public enum IdentityClaims {
    VOT("vot"),
    VTM("vtm"),
    SUB("sub"),
    CORE_IDENTITY("https://vocab.account.gov.uk/v1/coreIdentity"),
    CREDENTIAL_JWT("https://vocab.account.gov.uk/v1/credentialJWT");

    private String value;

    IdentityClaims(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
