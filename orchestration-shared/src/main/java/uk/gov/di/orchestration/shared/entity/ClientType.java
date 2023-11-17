package uk.gov.di.orchestration.shared.entity;

public enum ClientType {
    APP("app"),
    WEB("web");

    private String value;

    ClientType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
