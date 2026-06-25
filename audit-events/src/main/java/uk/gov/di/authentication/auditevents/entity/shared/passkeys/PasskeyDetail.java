package uk.gov.di.authentication.auditevents.entity.shared.passkeys;

public record PasskeyDetail(
        PasskeyAuthenticationRequest passkeyAuthenticationRequest,
        Long passkeyCounter,
        Boolean passkeyCredentialBackedUp,
        String passkeyCredentialDeviceType,
        boolean passkeyUserVerified,
        String passkeyVerificationFailureReason) {
    public static PasskeyDetail verificationFailed(
            String userVerification,
            Long passkeyCounter,
            Boolean passkeyCredentialBackedUp,
            String passkeyCredentialDeviceType,
            String verificationFailureReason) {
        var userVerified = false;
        return new PasskeyDetail(
                new PasskeyAuthenticationRequest(userVerification),
                passkeyCounter,
                passkeyCredentialBackedUp,
                passkeyCredentialDeviceType,
                userVerified,
                verificationFailureReason);
    }

    public static PasskeyDetail verificationCouldNotProceed(String verificationFailureReason) {
        var userVerified = false;
        return new PasskeyDetail(null, null, null, null, userVerified, verificationFailureReason);
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
}
