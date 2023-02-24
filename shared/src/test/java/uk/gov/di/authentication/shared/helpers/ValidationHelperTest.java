package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.services.CodeStorageService;

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

    private static Stream<String> invalidPhoneNumbers() {
        return Stream.of(
                "0123456789A",
                "0123456789",
                "012345678999",
                "01234567891",
                "202-456-1111",
                "02079460000");
    }

    @ParameterizedTest
    @MethodSource("invalidPhoneNumbers")
    void shouldReturnErrorIfMobileNumberIsInvalid(String phoneNumber) {
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1012),
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
                equalTo(Optional.of(ErrorResponse.ERROR_1012)));
    }

    private static Stream<Arguments> invalidPasswords() {
        return Stream.of(
                Arguments.of("", ErrorResponse.ERROR_1005),
                Arguments.of(null, ErrorResponse.ERROR_1005),
                Arguments.of("passw0r", ErrorResponse.ERROR_1006));
    }

    @ParameterizedTest
    @MethodSource("invalidPasswords")
    void shouldRejectInvalidPasswords(String password, ErrorResponse expectedResponse) {
        assertEquals(Optional.of(expectedResponse), ValidationHelper.validatePassword(password));
    }

    private static Stream<String> validPasswords() {
        return Stream.of("+pa?55worD", "computer-1", "passsssssssssssswwwwoooordddd-2");
    }

    @ParameterizedTest
    @MethodSource("validPasswords")
    void shouldAcceptValidPassword(String password) {
        assertEquals(Optional.empty(), ValidationHelper.validatePassword(password));
    }

    private static Stream<String> blankEmailAddresses() {
        return Stream.of("", "  ", "\t\t", System.lineSeparator() + System.lineSeparator(), null);
    }

    @ParameterizedTest
    @MethodSource("blankEmailAddresses")
    void shouldRejectBlankEmail(String emailAddress) {

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1003),
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
                Optional.of(ErrorResponse.ERROR_1004),
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
                Optional.of(ErrorResponse.ERROR_1019),
                ValidationHelper.validateEmailAddressUpdate(email, email));
    }

    @Test
    void shouldReturnErrorWhenExistingEmailIsInvalid() {
        String existingEmail = "joe.bloggs";
        String replacementEmail = "joe.bloggs@digital.cabinet-office.gov.uk";
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1004),
                ValidationHelper.validateEmailAddressUpdate(existingEmail, replacementEmail));
    }

    @Test
    void shouldReturnErrorWhenReplacementEmailIsInvalid() {
        String existingEmail = "joe.bloggs@digital.cabinet-office.gov.uk";
        String replacementEmail = "joe.bloggs";
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1004),
                ValidationHelper.validateEmailAddressUpdate(existingEmail, replacementEmail));
    }

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

    @Test
    void shouldSuccessfullyValidatePhoneNumberWhenNewNumberIsDifferentToCurrentNumber() {

        assertThat(
                ValidationHelper.validatePhoneNumber("+447911123456", "07700900222", INTEGRATION),
                equalTo(Optional.empty()));
    }

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
    void shouldSuccessfullyValidatePhoneNumberWhenNewNumberIsTestNumberAndEnvironmentIsNonProd(
            String testPhoneNumber) {

        assertThat(
                ValidationHelper.validatePhoneNumber("+447911123456", testPhoneNumber, INTEGRATION),
                equalTo(Optional.empty()));
    }

    @ParameterizedTest
    @MethodSource("testPhoneNumbers")
    void shouldReturnErrorWhenNewNumberIsTestNumberAndEnvironmentIsProd(String testPhoneNumber) {

        assertThat(
                ValidationHelper.validatePhoneNumber("+447911123456", testPhoneNumber, PRODUCTION),
                equalTo(Optional.of(ErrorResponse.ERROR_1012)));
    }

    @Test
    void shouldSuccessfullyValidatePhoneNumberWhenCurrentNumberIsNotPresent() {
        assertThat(
                ValidationHelper.validatePhoneNumber(null, "07700900222", INTEGRATION),
                equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnErrorWhenNewInternationPhoneNumberIsSameToCurrentNumber() {
        assertThat(
                ValidationHelper.validatePhoneNumber("+33645453322", "+33645453322", PRODUCTION),
                equalTo(Optional.of(ErrorResponse.ERROR_1044)));
    }

    @Test
    void shouldReturnErrorWhenNewNumberIsTheSameAsCurrentNumber() {
        assertThat(
                ValidationHelper.validatePhoneNumber("+447911123456", "07911123456", PRODUCTION),
                equalTo(Optional.of(ErrorResponse.ERROR_1044)));
    }

    @Test
    void shouldAcceptSupportedPhoneNumberTypes() {
        assertTrue(ValidationHelper.isAcceptedPhoneNumberType(MOBILE));
        assertTrue(ValidationHelper.isAcceptedPhoneNumberType(FIXED_LINE_OR_MOBILE));
        assertFalse(ValidationHelper.isAcceptedPhoneNumberType(FIXED_LINE));
    }

    @ParameterizedTest
    @MethodSource("validateCodeTestParameters")
    void shouldReturnCorrectErrorForCodeValidationScenarios(
            NotificationType notificationType,
            Optional<ErrorResponse> expectedResult,
            String input,
            int previousAttempts,
            Optional<String> storedCode) {

        var codeStorageService = mock(CodeStorageService.class);

        // This simulates the Redis increment counter's side effect which isn't captured
        previousAttempts++;

        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL_ADDRESS))
                .thenReturn(previousAttempts);

        assertEquals(
                expectedResult,
                ValidationHelper.validateVerificationCode(
                        notificationType, storedCode, input, codeStorageService, EMAIL_ADDRESS, 5));
    }

    private static Stream<Arguments> testPasswords() {
        return Stream.of(
                arguments("12345896", false),
                arguments("12a458Z6", true),
                arguments("a12458Z6", true),
                arguments("aZZZZkdfndsf!!@", false));
    }

    @ParameterizedTest
    @MethodSource("testPasswords")
    void shouldReturnFalseIfNoDigitOrOnlyDigits(String testPhoneNumber, boolean expectedResponse) {
        assertEquals(
                expectedResponse,
                ValidationHelper.hasAtLeastOneDigitAndOneNonDigit(testPhoneNumber));
    }
}
