package uk.gov.di.authentication.shared.entity.mfa;

public enum MFAMethodNotificationIdentifier {
    CHANGED_AUTHENTICATOR_APP("CHANGED_AUTHENTICATOR_APP"),
    CHANGED_DEFAULT_MFA("CHANGED_DEFAULT_MFA"),
    SWITCHED_MFA_METHODS("SWITCHED_MFA_METHODS");

    private String value;

    MFAMethodNotificationIdentifier(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
