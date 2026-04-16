package uk.gov.di.authentication.userpermissions.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.*;

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

    @ParameterizedTest
    @EnumSource(
            value = ForbiddenReason.class,
            names = {
                "EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT",
                "EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT"
            })
    void hasExceededOtpSubmissionLimitReturnsTrueForOtpSubmissionReasons(ForbiddenReason reason) {
        assertTrue(reason.hasExceededOtpSubmissionLimit());
    }

    @ParameterizedTest
    @EnumSource(
            value = ForbiddenReason.class,
            names = {
                "EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT",
                "EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT"
            },
            mode = EnumSource.Mode.EXCLUDE)
    void hasExceededOtpSubmissionLimitReturnsFalseForOtherReasons(ForbiddenReason reason) {
        assertFalse(reason.hasExceededOtpSubmissionLimit());
    }
}
