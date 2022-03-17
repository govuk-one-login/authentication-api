package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;

import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class ValidationServiceTest {

    public static final String VALID_CODE = "123456";
    public static final Optional<String> STORED_VALID_CODE = Optional.of(VALID_CODE);
    public static final String INVALID_CODE = "654321";
    private static final Optional<String> NO_CODE_STORED = Optional.empty();
    private final ValidationService validationService = new ValidationService();

    private static Stream<Arguments> validateCodeTestParameters() {
        return Stream.of(
                arguments(VERIFY_EMAIL, Optional.empty(), VALID_CODE, 0, STORED_VALID_CODE),
                arguments(VERIFY_PHONE_NUMBER, Optional.empty(), VALID_CODE, 0, STORED_VALID_CODE),
                arguments(MFA_SMS, Optional.empty(), VALID_CODE, 0, STORED_VALID_CODE),
                arguments(
                        RESET_PASSWORD_WITH_CODE,
                        Optional.empty(),
                        VALID_CODE,
                        0,
                        STORED_VALID_CODE),
                arguments(
                        VERIFY_EMAIL,
                        Optional.of(ErrorResponse.ERROR_1036),
                        VALID_CODE,
                        0,
                        NO_CODE_STORED),
                arguments(
                        VERIFY_PHONE_NUMBER,
                        Optional.of(ErrorResponse.ERROR_1037),
                        VALID_CODE,
                        0,
                        NO_CODE_STORED),
                arguments(
                        MFA_SMS,
                        Optional.of(ErrorResponse.ERROR_1035),
                        VALID_CODE,
                        0,
                        NO_CODE_STORED),
                arguments(
                        RESET_PASSWORD_WITH_CODE,
                        Optional.of(ErrorResponse.ERROR_1021),
                        VALID_CODE,
                        0,
                        NO_CODE_STORED),
                arguments(
                        VERIFY_EMAIL,
                        Optional.of(ErrorResponse.ERROR_1036),
                        INVALID_CODE,
                        1,
                        STORED_VALID_CODE),
                arguments(
                        VERIFY_PHONE_NUMBER,
                        Optional.of(ErrorResponse.ERROR_1037),
                        INVALID_CODE,
                        1,
                        STORED_VALID_CODE),
                arguments(
                        MFA_SMS,
                        Optional.of(ErrorResponse.ERROR_1035),
                        INVALID_CODE,
                        1,
                        STORED_VALID_CODE),
                arguments(
                        RESET_PASSWORD_WITH_CODE,
                        Optional.of(ErrorResponse.ERROR_1021),
                        INVALID_CODE,
                        1,
                        STORED_VALID_CODE),
                arguments(
                        VERIFY_EMAIL,
                        Optional.of(ErrorResponse.ERROR_1033),
                        INVALID_CODE,
                        6,
                        STORED_VALID_CODE),
                arguments(
                        VERIFY_PHONE_NUMBER,
                        Optional.of(ErrorResponse.ERROR_1034),
                        INVALID_CODE,
                        6,
                        STORED_VALID_CODE),
                arguments(
                        MFA_SMS,
                        Optional.of(ErrorResponse.ERROR_1027),
                        INVALID_CODE,
                        6,
                        STORED_VALID_CODE),
                arguments(
                        RESET_PASSWORD_WITH_CODE,
                        Optional.of(ErrorResponse.ERROR_1039),
                        INVALID_CODE,
                        6,
                        STORED_VALID_CODE));
    }

    @ParameterizedTest
    @MethodSource("validateCodeTestParameters")
    void shouldReturnCorrectErrorForCodeValidationScenarios(
            NotificationType notificationType,
            Optional<ErrorResponse> expectedResult,
            String input,
            int previousAttempts,
            Optional<String> storedCode) {
        Session session = mock(Session.class);
        when(session.getRetryCount()).thenReturn(previousAttempts);

        assertEquals(
                expectedResult,
                validationService.validateVerificationCode(
                        notificationType, storedCode, input, session, 5));
    }
}
