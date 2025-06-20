package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.exceptions.CodeRequestTypeNotFoundException;

import java.util.Objects;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;

class CodeRequestTypeTest {

    @Test
    void invalidNotificationTypeJourneyComboShouldThrowError() {
        assertThrows(
                CodeRequestTypeNotFoundException.class,
                () -> CodeRequestType.getCodeRequestType(VERIFY_EMAIL, JourneyType.SIGN_IN));
    }

    private static Stream<Arguments> deprecatedCodeRequestTypeExpectations() {
        return Stream.of(
                Arguments.of(MFAMethodType.EMAIL, JourneyType.SIGN_IN, null),
                Arguments.of(MFAMethodType.EMAIL, JourneyType.PASSWORD_RESET_MFA, null),
                Arguments.of(MFAMethodType.EMAIL, JourneyType.ACCOUNT_MANAGEMENT, null),
                Arguments.of(MFAMethodType.SMS, JourneyType.SIGN_IN, "SMS_SIGN_IN"),
                Arguments.of(MFAMethodType.SMS, JourneyType.PASSWORD_RESET_MFA, "PW_RESET_MFA_SMS"),
                Arguments.of(MFAMethodType.SMS, JourneyType.ACCOUNT_MANAGEMENT, null),
                Arguments.of(MFAMethodType.AUTH_APP, JourneyType.SIGN_IN, "AUTH_APP_SIGN_IN"),
                Arguments.of(
                        MFAMethodType.AUTH_APP,
                        JourneyType.PASSWORD_RESET_MFA,
                        "PW_RESET_MFA_AUTH_APP"),
                Arguments.of(MFAMethodType.AUTH_APP, JourneyType.ACCOUNT_MANAGEMENT, null));
    }

    // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
    @ParameterizedTest
    @MethodSource("deprecatedCodeRequestTypeExpectations")
    void shouldReturnExpectedDeprecatedCodeRequestTypeStringOrNull(
            MFAMethodType mfaMethodType, JourneyType journeyType, String expectedOutput) {
        String result =
                CodeRequestType.getDeprecatedCodeRequestTypeString(mfaMethodType, journeyType);
        assert (Objects.equals(result, expectedOutput));
    }
}
