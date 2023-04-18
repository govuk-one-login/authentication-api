package uk.gov.di.authentication.shared.entity;

public enum MFAMethodType {
    // TODO: "Empty" exists for now so that the enum can be looped over to lookup cache for a
    // (old-style) prefix that does not specify an MFA type e.g. when deleting all incorrect code
    // counters
    EMPTY(""),
    AUTH_APP("AUTH_APP"),
    SMS("SMS");

    private final String value;

    MFAMethodType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
