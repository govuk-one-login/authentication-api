package uk.gov.di.authentication.auditevents.entity.shared.passkeys;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasskeyDetailTest {

    @Test
    void createsVerificationFailed() {
        String passkeyRequestUserVerification = "testRequestUserVerification";
        Long passkeyCounter = 1L;
        Boolean passkeyCredentialBackedUp = true;
        String passkeyCredentialDeviceType = "testCredentialDeviceType";
        String passkeyVerificationFailureReason = "testVerificationFailureReason";

        var passkeyDetail =
                PasskeyDetail.verificationFailed(
                        passkeyRequestUserVerification,
                        passkeyCounter,
                        passkeyCredentialBackedUp,
                        passkeyCredentialDeviceType,
                        passkeyVerificationFailureReason);

        assertEquals(
                passkeyRequestUserVerification,
                passkeyDetail.passkeyAuthenticationRequest().passkeyRequestUserVerification());
        assertEquals(passkeyCounter, passkeyDetail.passkeyCounter());
        assertEquals(passkeyCredentialBackedUp, passkeyDetail.passkeyCredentialBackedUp());
        assertEquals(passkeyCredentialDeviceType, passkeyDetail.passkeyCredentialDeviceType());
        assertFalse(passkeyDetail.passkeyUserVerified());
        assertEquals(
                passkeyVerificationFailureReason, passkeyDetail.passkeyVerificationFailureReason());
        assertNull(passkeyDetail.passkeyAaguid());
    }
}
