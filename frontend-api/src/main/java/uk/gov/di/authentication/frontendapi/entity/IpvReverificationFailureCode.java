package uk.gov.di.authentication.frontendapi.entity;

public enum IpvReverificationFailureCode {
    NO_IDENTITY_AVAILABLE("no_identity_available"),
    IDENTITY_CHECK_INCOMPLETE("identity_check_incomplete"),
    IDENTITY_CHECK_FAILED("identity_check_failed"),
    IDENTITY_DID_NOT_MATCH("identity_did_not_match");

    private String value;

    IpvReverificationFailureCode(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static IpvReverificationFailureCode fromValue(String value) {
        for (IpvReverificationFailureCode e : IpvReverificationFailureCode.values()) {
            if (e.getValue().equals(value)) {
                return e;
            }
        }
        throw new IllegalArgumentException("No enum constant with value " + value);
    }

    public static boolean isValid(String value) {
        for (IpvReverificationFailureCode e : IpvReverificationFailureCode.values()) {
            if (e.getValue().equals(value)) {
                return true;
            }
        }
        return false;
    }
}
