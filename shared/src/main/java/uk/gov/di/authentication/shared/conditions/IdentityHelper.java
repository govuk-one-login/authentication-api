package uk.gov.di.authentication.shared.conditions;

public class IdentityHelper {

    private IdentityHelper() {}

    public static boolean identityRequired(
            boolean identityRequired,
            boolean clientSupportsIdentityVerification,
            boolean identityEnabled) {
        return clientSupportsIdentityVerification && identityEnabled && identityRequired;
    }
}
