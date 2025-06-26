package uk.gov.di.authentication.shared.entity.mfa;

public enum MFAMethodEmailNotificationIdentifier {
    CHANGED_AUTHENTICATOR_APP("CHANGED_AUTHENTICATOR_APP"),
    CHANGED_SMS("CHANGED_SMS"),
    CHANGED_DEFAULT_MFA("CHANGED_DEFAULT_MFA"),
    SWITCHED_MFA_METHODS("SWITCHED_MFA_METHODS");

    private String value;

    MFAMethodEmailNotificationIdentifier(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
