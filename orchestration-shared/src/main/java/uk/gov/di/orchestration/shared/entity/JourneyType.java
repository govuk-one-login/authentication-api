package uk.gov.di.orchestration.shared.entity;

public enum JourneyType {
    ACCOUNT_RECOVERY("ACCOUNT_RECOVERY"),
    REGISTRATION("REGISTRATION"),
    SIGN_IN("SIGN_IN"),
    PASSWORD_RESET("PASSWORD_RESET"),
    PASSWORD_RESET_MFA("PASSWORD_RESET_MFA"),
    REAUTHENTICATION("REAUTHENTICATION"),
    ACCOUNT_MANAGEMENT("ACCOUNT_MANAGEMENT");

    private String value;

    JourneyType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
