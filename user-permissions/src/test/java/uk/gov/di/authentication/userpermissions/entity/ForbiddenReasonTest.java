package uk.gov.di.authentication.userpermissions.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ForbiddenReasonTest {

    @Test
    void shouldHaveCorrectEnumValues() {
        // Then
        assertEquals(
                "EXCEEDED_INCORRECT_EMAIL_ADDRESS_SUBMISSION_LIMIT",
                ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_ADDRESS_SUBMISSION_LIMIT.name());
        assertEquals(
                "EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT",
                ForbiddenReason.EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT.name());
        assertEquals(
                "EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT",
                ForbiddenReason.EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT.name());
        assertEquals(
                "EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT",
                ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT.name());
        assertEquals(
                "EXCEEDED_SEND_MFA_OTP_NOTIFICATION_LIMIT",
                ForbiddenReason.EXCEEDED_SEND_MFA_OTP_NOTIFICATION_LIMIT.name());
        assertEquals(
                "EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT",
                ForbiddenReason.EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT.name());
    }

    @Test
    void shouldBeAbleToConvertToString() {
        // When
        String result = ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT.toString();

        // Then
        assertNotNull(result);
        assertEquals("EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT", result);
    }
}
