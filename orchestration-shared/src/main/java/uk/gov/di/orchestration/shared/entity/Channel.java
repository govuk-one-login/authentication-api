package uk.gov.di.orchestration.shared.entity;

public enum Channel {
    WEB("WEB"),
    STRATEGIC_APP("STRATEGIC_APP");

    private final String value;

    Channel(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
