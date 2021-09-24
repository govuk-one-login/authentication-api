package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class ValidationServiceTest {

    private final ValidationService validationService = new ValidationService();

    @Test
    public void shouldRejectEmptyEmail() {
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1003), validationService.validateEmailAddress(""));
    }

    @Test
    public void shouldRejectBlankEmail() {
        var spacesEmail = "  ";
        var tabsEmail = "\t\t";
        var newlinesEmail = System.lineSeparator() + System.lineSeparator();

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1003),
                validationService.validateEmailAddress(spacesEmail));
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1003),
                validationService.validateEmailAddress(tabsEmail));
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1003),
                validationService.validateEmailAddress(newlinesEmail));
    }

    @Test
    public void shouldRejectMalformattedEmail() {
        var noAtsEmail = "test.example.gov.uk";
        var multipleAtsEmail = "test@example@gov.uk";
        var noDotsEmail = "test@examplegovuk";

        assertEquals(
                Optional.of(ErrorResponse.ERROR_1004),
                validationService.validateEmailAddress(noAtsEmail));
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1004),
                validationService.validateEmailAddress(multipleAtsEmail));
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1004),
                validationService.validateEmailAddress(noDotsEmail));
    }

    @Test
    public void shouldAcceptValidEmail() {
        var validEmail = "test@example.gov.uk";

        assertTrue(validationService.validateEmailAddress(validEmail).isEmpty());
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

    @Test
    public void shouldReturnErrorIsPhoneNumberContainsLetter() {
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1012),
                validationService.validatePhoneNumber("0123456789A"));
    }

    @Test
    public void shouldReturnErrorIsPhoneNumberIsLessThan10Characters() {
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1012),
                validationService.validatePhoneNumber("0123456789"));
    }

    @Test
    public void shouldReturnErrorIsPhoneNumberIsTooLong() {
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1012),
                validationService.validatePhoneNumber("012345678999"));
    }

    @Test
    public void shouldNotReturnErrorIsPhoneNumberIsValid() {
        assertEquals(Optional.empty(), validationService.validatePhoneNumber("01234567891"));
    }

    @Test
    public void shouldReturnErrorIsPhoneNumberContainsNonnumericCharacters() {
        assertEquals(
                Optional.of(ErrorResponse.ERROR_1012),
                validationService.validatePhoneNumber("202-456-1111"));
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
