package uk.gov.di.authentication.shared.entity;

public enum MFAMethodPriorityIdentifier {
    
    PRIMARY("PRIMARY"),
    SECONDARY("SECONDARY");

    private String value;

    MFAMethodPriorityIdentifier(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
