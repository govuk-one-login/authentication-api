package uk.gov.di.authentication.auditevents.entity.shared.passkeys;

public record PasskeyDetail(
        PasskeyAuthenticationRequest passkeyAuthenticationRequest,
        Long passkeyCounter,
        Boolean passkeyCredentialBackedUp,
        String passkeyCredentialDeviceType,
        boolean passkeyUserVerified,
        String passkeyAuthenticationFailureReason) {
    public static PasskeyDetail verificationFailed(
            String userVerification,
            long passkeyCounter,
            boolean passkeyCredentialBackedUp,
            String passkeyCredentialDeviceType,
            String authenticationFailureReason) {
        var userVerified = false;
        return new PasskeyDetail(
                new PasskeyAuthenticationRequest(userVerification),
                passkeyCounter,
                passkeyCredentialBackedUp,
                passkeyCredentialDeviceType,
                userVerified,
                authenticationFailureReason);
    }

    public static PasskeyDetail verificationCouldNotProceed(String authenticationFailureReason) {
        var userVerified = false;
        return new PasskeyDetail(null, null, null, null, userVerified, authenticationFailureReason);
    }

    public static PasskeyDetail verificationSuccessful(
            String userVerification,
            long passkeyCounter,
            boolean passkeyCredentialBackedUp,
            String passkeyCredentialDeviceType) {
        var userVerified = true;
        return new PasskeyDetail(
                new PasskeyAuthenticationRequest(userVerification),
                passkeyCounter,
                passkeyCredentialBackedUp,
                passkeyCredentialDeviceType,
                userVerified,
                null);
    }

    public static PasskeyDetail authenticationSuccessful(
            long passkeyCounter,
            boolean passkeyCredentialBackedUp,
            String passkeyCredentialDeviceType) {
        var userVerified = false;
        return new PasskeyDetail(
                null,
                passkeyCounter,
                passkeyCredentialBackedUp,
                passkeyCredentialDeviceType,
                userVerified,
                null);
    }
}
