package uk.gov.di.authentication.frontendapi;

public enum IPVReverificationFailureReason {
    JWT_CREATION_ERROR("jwt_creation_error");

    private final String value;

    IPVReverificationFailureReason(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
