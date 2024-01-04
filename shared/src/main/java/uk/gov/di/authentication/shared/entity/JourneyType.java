package uk.gov.di.authentication.shared.entity;

public enum JourneyType {
    ACCOUNT_RECOVERY("ACCOUNT_RECOVERY"),
    REGISTRATION("REGISTRATION"),
    SIGN_IN("SIGN_IN"),
    PASSWORD_RESET("PASSWORD_RESET"),
    PASSWORD_RESET_MFA("PASSWORD_RESET_MFA"),
    REAUTHENTICATE_MFA("REAUTHENTICATE_MFA");

    private String value;

    JourneyType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
