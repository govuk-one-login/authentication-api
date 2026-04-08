package uk.gov.di.orchestration.shared.entity;

public enum Channel {
    WEB("web"),
    STRATEGIC_APP("strategic_app"),
    GENERIC_APP("generic_app");

    private final String value;

    Channel(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
