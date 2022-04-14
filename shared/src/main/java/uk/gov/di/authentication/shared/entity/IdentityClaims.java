package uk.gov.di.authentication.shared.entity;

public enum IdentityClaims {
    VOT("vot"),
    VTM("vtm"),
    SUB("sub");

    private String value;

    IdentityClaims(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
