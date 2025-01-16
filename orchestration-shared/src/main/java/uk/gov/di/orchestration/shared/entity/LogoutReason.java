package uk.gov.di.orchestration.shared.entity;

public enum LogoutReason {
    FRONT_CHANNEL("front-channel"),
    INTERVENTION("intervention"),
    REAUTHENTICATION_FAILURE("reauthentication-failure"),
    MAX_AGE_EXPIRY("max-session-age");

    private String value;

    LogoutReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
