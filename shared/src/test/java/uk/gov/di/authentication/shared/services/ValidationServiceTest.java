package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;

import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class ValidationServiceTest {

    private final ValidationService validationService = new ValidationService();

    private static Stream<String> blankEmailAddresses() {
        return Stream.of("", "  ", "\t\t", System.lineSeparator() + System.lineSeparator(), null);
    }

    @ParameterizedTest
    @MethodSource("blankEmailAddresses")
    public void shouldRejectBlankEmail(String emailAddress) {

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1003),
                validationService.validateEmailAddress(emailAddress));
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
    public void shouldRejectMalformattedEmail(String emailAddress) {

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1004),
                validationService.validateEmailAddress(emailAddress));
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
    public void shouldAcceptValidEmail(String emailAddress) {

        assertTrue(validationService.validateEmailAddress(emailAddress).isEmpty());
    }

    @Test
    public void shouldRejectPasswordLessThan8Characters() {
        var shortPassword = "passw0r";

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1006),
                validationService.validatePassword(shortPassword));
    }

    @Test
    public void shouldRejectEmptyPassword() {
        assertEquals(Optional.of(ErrorResponse.ERROR_1005), validationService.validatePassword(""));
    }

    @Test
    public void shouldNotThrowNullPointerIfPasswordInputsAreNull() {
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1005), validationService.validatePassword(null));
    }

    private static Stream<String> invalidPhoneNumbers() {
        return Stream.of(
                "0123456789A", "0123456789", "012345678999", "01234567891", "202-456-1111");
    }

    @ParameterizedTest
    @MethodSource("invalidPhoneNumbers")
    public void shouldReturnErrorIfMobileNumberIsInvalid(String phoneNumber) {
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1012),
                validationService.validatePhoneNumber(phoneNumber));
    }

    @Test
    public void shouldReturnCorrectStateWhenPhoneCodeMatchesStored() {
        assertEquals(
                SessionAction.USER_ENTERED_VALID_PHONE_VERIFICATION_CODE,
                validationService.validateVerificationCode(
                        VERIFY_PHONE_NUMBER,
                        Optional.of("123456"),
                        "123456",
                        mock(Session.class),
                        5));
    }

    @Test
    public void shouldReturnCorrectStateWhenStoredPhoneCodeIsEmpty() {
        assertEquals(
                SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE,
                validationService.validateVerificationCode(
                        VERIFY_PHONE_NUMBER, Optional.empty(), "123456", mock(Session.class), 5));
    }

    @Test
    public void
            shouldReturnCorrectStateWhenStoredPhoneCodeDoesMatchInputAndRetryLimitHasNotBeenReached() {
        Session session = mock(Session.class);
        when(session.getRetryCount()).thenReturn(1);
        assertEquals(
                SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE,
                validationService.validateVerificationCode(
                        VERIFY_PHONE_NUMBER, Optional.of("654321"), "123456", session, 5));
    }

    @Test
    public void
            shouldReturnCorrectStateWhenStoredPhoneCodeDoesMatchInputAndRetryLimitHasBeenReached() {
        Session session = mock(Session.class);
        when(session.getRetryCount()).thenReturn(6);
        assertEquals(
                SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES,
                validationService.validateVerificationCode(
                        VERIFY_PHONE_NUMBER, Optional.of("654321"), "123456", session, 5));
    }

    @Test
    public void shouldReturnCorrectStateWhenEmailCodeMatchesStored() {
        assertEquals(
                SessionAction.USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE,
                validationService.validateVerificationCode(
                        VERIFY_EMAIL, Optional.of("123456"), "123456", mock(Session.class), 5));
    }

    @Test
    public void shouldReturnCorrectStateWhenStoredEmailCodeIsEmpty() {
        assertEquals(
                SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE,
                validationService.validateVerificationCode(
                        VERIFY_EMAIL, Optional.empty(), "123456", mock(Session.class), 5));
    }

    @Test
    public void
            shouldReturnCorrectStateWhenStoredEmailCodeDoesMatchInputAndRetryLimitHasNotBeenReached() {
        Session session = mock(Session.class);
        when(session.getRetryCount()).thenReturn(1);
        assertEquals(
                SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE,
                validationService.validateVerificationCode(
                        VERIFY_EMAIL, Optional.of("654321"), "123456", session, 5));
    }

    @Test
    public void
            shouldReturnCorrectStateWhenStoredEmailCodeDoesMatchInputAndRetryLimitHasBeenReached() {
        Session session = mock(Session.class);
        when(session.getRetryCount()).thenReturn(6);
        assertEquals(
                SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES,
                validationService.validateVerificationCode(
                        VERIFY_EMAIL, Optional.of("654321"), "123456", session, 5));
    }

    @Test
    public void shouldReturnCorrectStateWhenMfaCodeMatchesStored() {
        assertEquals(
                SessionAction.USER_ENTERED_VALID_MFA_CODE,
                validationService.validateVerificationCode(
                        MFA_SMS, Optional.of("123456"), "123456", mock(Session.class), 5));
    }

    @Test
    public void shouldReturnCorrectStateWhenStoredMfaCodeIsEmpty() {
        assertEquals(
                SessionAction.USER_ENTERED_INVALID_MFA_CODE,
                validationService.validateVerificationCode(
                        MFA_SMS, Optional.empty(), "123456", mock(Session.class), 5));
    }

    @Test
    public void
            shouldReturnCorrectStateWhenStoredMfaCodeDoesMatchInputAndRetryLimitHasNotBeenReached() {
        Session session = mock(Session.class);
        when(session.getRetryCount()).thenReturn(1);
        assertEquals(
                SessionAction.USER_ENTERED_INVALID_MFA_CODE,
                validationService.validateVerificationCode(
                        MFA_SMS, Optional.of("654321"), "123456", session, 5));
    }

    @Test
    public void
            shouldReturnCorrectStateWhenStoredMfaCodeDoesMatchInputAndRetryLimitHasBeenReached() {
        Session session = mock(Session.class);
        when(session.getRetryCount()).thenReturn(6);
        assertEquals(
                SessionAction.USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES,
                validationService.validateVerificationCode(
                        MFA_SMS, Optional.of("654321"), "123456", session, 5));
    }

    @Test
    public void shouldReturnErrorWhenEmailAddressesAreTheSame() {
        String email = "joe.bloggs@digital.cabinet-office.gov.uk";
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1019),
                validationService.validateEmailAddressUpdate(email, email));
    }

    @Test
    public void shouldReturnErrorWhenExistingEmailIsInvalid() {
        String existingEmail = "joe.bloggs";
        String replacementEmail = "joe.bloggs@digital.cabinet-office.gov.uk";
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1004),
                validationService.validateEmailAddressUpdate(existingEmail, replacementEmail));
    }

    @Test
    public void shouldReturnErrorWhenReplacementEmailIsInvalid() {
        String existingEmail = "joe.bloggs@digital.cabinet-office.gov.uk";
        String replacementEmail = "joe.bloggs";
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1004),
                validationService.validateEmailAddressUpdate(existingEmail, replacementEmail));
    }
}
