package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;
import java.util.stream.Stream;

import static com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType.FIXED_LINE;
import static com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType.FIXED_LINE_OR_MOBILE;
import static com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberType.MOBILE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

class ValidationHelperTest {

    public static final String VALID_CODE = "123456";
    public static final Optional<String> STORED_VALID_CODE = Optional.of(VALID_CODE);
    public static final String INVALID_CODE = "654321";
    private static final Optional<String> NO_CODE_STORED = Optional.empty();
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String PRODUCTION = "production";
    private static final String INTEGRATION = "integration";

    private static final ConfigurationService configurationServiceMock =
            mock(ConfigurationService.class);

    @Nested
    class PhoneNumberValidatorTests {
        private static Stream<String> testPhoneNumbers() {
            return Stream.of(
                    "07700900222",
                    "07700900000",
                    "07700900111",
                    "+447700900000",
                    "+447700900111",
                    "+447700900222");
        }

        @ParameterizedTest
        @MethodSource("testPhoneNumbers")
        void shouldAcceptTestNumberForSmokeTest(String testPhoneNumber) {
            assertThat(
                    ValidationHelper.validatePhoneNumber(testPhoneNumber, PRODUCTION, true),
                    equalTo(Optional.empty()));
        }

        @ParameterizedTest
        @MethodSource("testPhoneNumbers")
        void shouldRejectTestNumberWhenNotSmokeTest(String testPhoneNumber) {
            assertThat(
                    ValidationHelper.validatePhoneNumber(testPhoneNumber, PRODUCTION, false),
                    equalTo(Optional.of(ErrorResponse.INVALID_PHONE_NUMBER)));
        }

        private static Stream<String> invalidPhoneNumbers() {
            return Stream.of(
                    "0123456789A",
                    "0123456789",
                    "012345678999",
                    "01234567891",
                    "202-456-1111",
                    "02079460000",
                    "00",
                    "12345678901234567890123456",
                    "surely can't be a number");
        }

        @ParameterizedTest
        @MethodSource("invalidPhoneNumbers")
        void shouldReturnErrorIfMobileNumberIsInvalid(String phoneNumber) {
            assertEquals(
                    Optional.of(ErrorResponse.INVALID_PHONE_NUMBER),
                    ValidationHelper.validatePhoneNumber(phoneNumber, PRODUCTION, false));
        }

        private static Stream<String> internationalPhoneNumbers() {
            return Stream.of(
                    "+447316763843",
                    "+4407316763843",
                    "+33645453322",
                    "+330645453322",
                    "+447316763843",
                    "+447316763843",
                    "+33645453322",
                    "+33645453322");
        }

        @ParameterizedTest
        @MethodSource("internationalPhoneNumbers")
        void shouldAcceptValidInternationPhoneNumbers(String phoneNumber) {
            assertThat(
                    ValidationHelper.validatePhoneNumber(phoneNumber, PRODUCTION, false),
                    equalTo(Optional.empty()));
        }

        @Test
        void shouldAcceptValidBritishPhoneNumbers() {
            assertThat(
                    ValidationHelper.validatePhoneNumber("+4407911123456", PRODUCTION, false),
                    equalTo(Optional.empty()));
        }

        @Test
        void shouldAcceptSupportedPhoneNumberTypes() {
            assertTrue(ValidationHelper.isAcceptedPhoneNumberType(MOBILE));
            assertTrue(ValidationHelper.isAcceptedPhoneNumberType(FIXED_LINE_OR_MOBILE));
            assertFalse(ValidationHelper.isAcceptedPhoneNumberType(FIXED_LINE));
        }
    }

    @Nested
    class EmailValidatorTests {

        private static Stream<String> blankEmailAddresses() {
            return Stream.of(
                    "", "  ", "\t\t", System.lineSeparator() + System.lineSeparator(), null);
        }

        @ParameterizedTest
        @MethodSource("blankEmailAddresses")
        void shouldRejectBlankEmail(String emailAddress) {

            assertEquals(
                    Optional.of(ErrorResponse.EMAIL_ADDRESS_EMPTY),
                    ValidationHelper.validateEmailAddress(emailAddress));
        }

        private static Stream<String> invalidEmailAddresses() {
            return Stream.of(
                    "test.example.gov.uk",
                    "test@example@gov.uk",
                    "test@examplegovuk",
                    "testµ@example.gov.uk",
                    "email@123.123.123.123",
                    "email@[123.123.123.123]",
                    "plainaddress",
                    "@no-local-part.com",
                    "Outlook Contact <outlook-contact@domain.com>",
                    "no-at.domain.com",
                    "no-tld@domain",
                    ";beginning-semicolon@domain.co.uk",
                    "middle-semicolon@domain.co;uk",
                    "trailing-semicolon@domain.com;",
                    "\"email+leading-quotes@domain.com",
                    "email+middle\"-quotes@domain.com",
                    "quoted-local-part\"@domain.com",
                    "\"quoted@domain.com\"",
                    "lots-of-dots@domain..gov..uk",
                    "two-dots..in-local@domain.com",
                    "multiple@domains@domain.com",
                    "spaces in local@domain.com",
                    "spaces-in-domain@dom ain.com",
                    "underscores-in-domain@dom_ain.com",
                    "pipe-in-domain@example.com|gov.uk",
                    "comma,in-local@gov.uk",
                    "comma-in-domain@domain,gov.uk",
                    "pound-sign-in-local£@domain.com",
                    "local-with-’-apostrophe@domain.com",
                    "local-with-”-quotes@domain.com",
                    "domain-starts-with-a-dot@.domain.com",
                    "brackets(in)local@domain.com",
                    "incorrect-punycode@xn---something.com");
        }

        @ParameterizedTest
        @MethodSource("invalidEmailAddresses")
        void shouldRejectMalformattedEmail(String emailAddress) {

            assertEquals(
                    Optional.of(ErrorResponse.INVALID_EMAIL_FORMAT),
                    ValidationHelper.validateEmailAddress(emailAddress));
        }

        private static Stream<String> validEmailAddresses() {
            return Stream.of(
                    "test@example.gov.uk",
                    "test@example.com",
                    "test@example.info",
                    "email@domain.com",
                    "email@domain.COM",
                    "firstname.lastname@domain.com",
                    "firstname.o\'lastname@domain.com",
                    "email@subdomain.domain.com",
                    "firstname+lastname@domain.com");
        }

        @ParameterizedTest
        @MethodSource("validEmailAddresses")
        void shouldAcceptValidEmail(String emailAddress) {

            assertTrue(ValidationHelper.validateEmailAddress(emailAddress).isEmpty());
        }

        @Test
        void shouldReturnErrorWhenEmailAddressesAreTheSame() {
            String email = "joe.bloggs@digital.cabinet-office.gov.uk";
            assertEquals(
                    Optional.of(ErrorResponse.EMAIL_ADDRESSES_MATCH),
                    ValidationHelper.validateEmailAddressUpdate(email, email));
        }

        @Test
        void shouldReturnErrorWhenExistingEmailIsInvalid() {
            String existingEmail = "joe.bloggs";
            String replacementEmail = "joe.bloggs@digital.cabinet-office.gov.uk";
            assertEquals(
                    Optional.of(ErrorResponse.INVALID_EMAIL_FORMAT),
                    ValidationHelper.validateEmailAddressUpdate(existingEmail, replacementEmail));
        }

        @Test
        void shouldReturnErrorWhenReplacementEmailIsInvalid() {
            String existingEmail = "joe.bloggs@digital.cabinet-office.gov.uk";
            String replacementEmail = "joe.bloggs";
            assertEquals(
                    Optional.of(ErrorResponse.INVALID_EMAIL_FORMAT),
                    ValidationHelper.validateEmailAddressUpdate(existingEmail, replacementEmail));
        }
    }

    private static Stream<Arguments> validateCodeTestParameters() {
        return Stream.of(
                arguments(
                        VERIFY_EMAIL,
                        JourneyType.PASSWORD_RESET,
                        Optional.empty(),
                        VALID_CODE,
                        0,
                        STORED_VALID_CODE),
                arguments(
                        VERIFY_PHONE_NUMBER,
                        JourneyType.REGISTRATION,
                        Optional.empty(),
                        VALID_CODE,
                        0,
                        STORED_VALID_CODE),
                arguments(
                        MFA_SMS,
                        JourneyType.PASSWORD_RESET_MFA,
                        Optional.empty(),
                        VALID_CODE,
                        0,
                        STORED_VALID_CODE),
                arguments(
                        RESET_PASSWORD_WITH_CODE,
                        JourneyType.PASSWORD_RESET,
                        Optional.empty(),
                        VALID_CODE,
                        0,
                        STORED_VALID_CODE),
                arguments(
                        VERIFY_EMAIL,
                        JourneyType.PASSWORD_RESET,
                        Optional.of(ErrorResponse.INVALID_EMAIL_CODE_ENTERED),
                        VALID_CODE,
                        0,
                        NO_CODE_STORED),
                arguments(
                        VERIFY_PHONE_NUMBER,
                        JourneyType.ACCOUNT_RECOVERY,
                        Optional.of(ErrorResponse.INVALID_PHONE_CODE_ENTERED),
                        VALID_CODE,
                        0,
                        NO_CODE_STORED),
                arguments(
                        MFA_SMS,
                        JourneyType.REAUTHENTICATION,
                        Optional.of(ErrorResponse.INVALID_MFA_CODE_ENTERED),
                        VALID_CODE,
                        0,
                        NO_CODE_STORED),
                arguments(
                        RESET_PASSWORD_WITH_CODE,
                        JourneyType.PASSWORD_RESET,
                        Optional.of(ErrorResponse.INVALID_PW_RESET_CODE),
                        VALID_CODE,
                        0,
                        NO_CODE_STORED),
                arguments(
                        VERIFY_EMAIL,
                        JourneyType.PASSWORD_RESET,
                        Optional.of(ErrorResponse.INVALID_EMAIL_CODE_ENTERED),
                        INVALID_CODE,
                        1,
                        STORED_VALID_CODE),
                arguments(
                        VERIFY_PHONE_NUMBER,
                        JourneyType.REGISTRATION,
                        Optional.of(ErrorResponse.INVALID_PHONE_CODE_ENTERED),
                        INVALID_CODE,
                        1,
                        STORED_VALID_CODE),
                arguments(
                        MFA_SMS,
                        JourneyType.PASSWORD_RESET_MFA,
                        Optional.of(ErrorResponse.INVALID_MFA_CODE_ENTERED),
                        INVALID_CODE,
                        1,
                        STORED_VALID_CODE),
                arguments(
                        RESET_PASSWORD_WITH_CODE,
                        JourneyType.PASSWORD_RESET,
                        Optional.of(ErrorResponse.INVALID_PW_RESET_CODE),
                        INVALID_CODE,
                        1,
                        STORED_VALID_CODE),
                arguments(
                        VERIFY_EMAIL,
                        JourneyType.PASSWORD_RESET,
                        Optional.of(ErrorResponse.TOO_MANY_EMAIL_CODES_ENTERED),
                        INVALID_CODE,
                        6,
                        STORED_VALID_CODE),
                arguments(
                        VERIFY_PHONE_NUMBER,
                        JourneyType.REGISTRATION,
                        Optional.of(ErrorResponse.TOO_MANY_PHONE_CODES_ENTERED),
                        INVALID_CODE,
                        6,
                        STORED_VALID_CODE),
                arguments(
                        MFA_SMS,
                        JourneyType.PASSWORD_RESET_MFA,
                        Optional.of(ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED),
                        INVALID_CODE,
                        6,
                        STORED_VALID_CODE),
                arguments(
                        RESET_PASSWORD_WITH_CODE,
                        JourneyType.PASSWORD_RESET,
                        Optional.of(ErrorResponse.TOO_MANY_INVALID_PW_RESET_CODES_ENTERED),
                        INVALID_CODE,
                        6,
                        STORED_VALID_CODE),
                arguments(
                        VERIFY_PHONE_NUMBER,
                        JourneyType.PASSWORD_RESET_MFA,
                        Optional.of(ErrorResponse.TOO_MANY_PHONE_CODES_ENTERED),
                        INVALID_CODE,
                        100,
                        STORED_VALID_CODE),
                arguments(
                        VERIFY_PHONE_NUMBER,
                        JourneyType.PASSWORD_RESET_MFA,
                        Optional.of(ErrorResponse.TOO_MANY_PHONE_CODES_ENTERED),
                        INVALID_CODE,
                        100,
                        STORED_VALID_CODE));
    }

    @ParameterizedTest
    @MethodSource("validateCodeTestParameters")
    void shouldReturnCorrectErrorForCodeValidationScenarios(
            NotificationType notificationType,
            JourneyType journeyType,
            Optional<ErrorResponse> expectedResult,
            String input,
            int previousAttempts,
            Optional<String> storedCode) {

        var codeStorageService = mock(CodeStorageService.class);

        // This simulates the Redis increment counter's side effect which isn't captured
        previousAttempts++;

        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL_ADDRESS))
                .thenReturn(previousAttempts);

        when(configurationServiceMock.getCodeMaxRetries()).thenReturn(5);
        when(configurationServiceMock.supportAccountCreationTTL()).thenReturn(false);

        assertEquals(
                expectedResult,
                ValidationHelper.validateVerificationCode(
                        notificationType,
                        journeyType,
                        storedCode,
                        input,
                        codeStorageService,
                        EMAIL_ADDRESS,
                        configurationServiceMock));
    }

    @ParameterizedTest
    @MethodSource("validateCodeTestParameters")
    void shouldIncreaseRetryCountWithCorrectTTL(
            NotificationType notificationType,
            JourneyType journeyType,
            Optional<ErrorResponse> expectedResult,
            String input,
            int previousAttempts,
            Optional<String> storedCode) {

        var codeStorageService = mock(CodeStorageService.class);

        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL_ADDRESS)).thenReturn(1);
        when(configurationServiceMock.getCodeMaxRetries()).thenReturn(5);
        when(configurationServiceMock.supportAccountCreationTTL()).thenReturn(true);

        ValidationHelper.validateVerificationCode(
                notificationType,
                journeyType,
                Optional.empty(),
                input,
                codeStorageService,
                EMAIL_ADDRESS,
                configurationServiceMock);

        if (journeyType != JourneyType.REAUTHENTICATION) {
            if (notificationType == VERIFY_EMAIL) {
                verify(codeStorageService)
                        .increaseIncorrectMfaCodeAttemptsCountAccountCreation(EMAIL_ADDRESS);
            } else {
                verify(codeStorageService).increaseIncorrectMfaCodeAttemptsCount(EMAIL_ADDRESS);
            }
        }
    }
}
