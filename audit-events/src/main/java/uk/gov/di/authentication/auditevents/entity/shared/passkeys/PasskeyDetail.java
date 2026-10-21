package uk.gov.di.authentication.auditevents.entity.shared.passkeys;

public record PasskeyDetail(
        PasskeyAuthenticationRequest passkeyAuthenticationRequest,
        Long passkeyCounter,
        Boolean passkeyCredentialBackedUp,
        String passkeyCredentialDeviceType,
        Boolean passkeyUserVerified,
        String passkeyVerificationFailureReason,
        String passkeyAaguid) {

    public static PasskeyDetail verificationFailed(
            String passkeyRequestUserVerification,
            Long passkeyCounter,
            Boolean passkeyCredentialBackedUp,
            String passkeyCredentialDeviceType,
            String passkeyVerificationFailureReason) {
        var passkeyUserVerified = false;
        return new PasskeyDetail(
                new PasskeyAuthenticationRequest(passkeyRequestUserVerification),
                passkeyCounter,
                passkeyCredentialBackedUp,
                passkeyCredentialDeviceType,
                passkeyUserVerified,
                passkeyVerificationFailureReason,
                null);
    }

    public static PasskeyDetail verificationCouldNotProceed(
            String passkeyVerificationFailureReason) {
        var passkeyUserVerified = false;
        return new PasskeyDetail(
                null,
                null,
                null,
                null,
                passkeyUserVerified,
                passkeyVerificationFailureReason,
                null);
    }

    public static PasskeyDetail verificationSuccessful(
            String passkeyRequestUserVerification,
            long passkeyCounter,
            boolean passkeyCredentialBackedUp,
            String passkeyCredentialDeviceType) {
        var passkeyUserVerified = true;
        return new PasskeyDetail(
                new PasskeyAuthenticationRequest(passkeyRequestUserVerification),
                passkeyCounter,
                passkeyCredentialBackedUp,
                passkeyCredentialDeviceType,
                passkeyUserVerified,
                null,
                null);
    }
}
