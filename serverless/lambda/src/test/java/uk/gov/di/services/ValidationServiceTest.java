package uk.gov.di.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_NOT_VALID;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_NOT_VALID;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_VERIFIED;

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
                PHONE_NUMBER_CODE_VERIFIED,
                validationService.validatePhoneVerificationCode(
                        Optional.of("123456"), "123456", mock(Session.class), 5));
    }

    @Test
    public void shouldReturnCorrectStateWhenStoredPhoneCodeIsEmpty() {
        assertEquals(
                PHONE_NUMBER_CODE_NOT_VALID,
                validationService.validatePhoneVerificationCode(
                        Optional.empty(), "123456", mock(Session.class), 5));
    }

    @Test
    public void
            shouldReturnCorrectStateWhenStoredPhoneCodeDoesMatchInputAndRetryLimitHasNotBeenReached() {
        Session session = mock(Session.class);
        when(session.getRetryCount()).thenReturn(1);
        assertEquals(
                PHONE_NUMBER_CODE_NOT_VALID,
                validationService.validatePhoneVerificationCode(
                        Optional.of("654321"), "123456", session, 5));
    }

    @Test
    public void
            shouldReturnCorrectStateWhenStoredPhoneCodeDoesMatchInputAndRetryLimitHasBeenReached() {
        Session session = mock(Session.class);
        when(session.getRetryCount()).thenReturn(6);
        assertEquals(
                PHONE_NUMBER_CODE_MAX_RETRIES_REACHED,
                validationService.validatePhoneVerificationCode(
                        Optional.of("654321"), "123456", session, 5));
    }

    @Test
    public void shouldReturnCorrectStateWhenEmailCodeMatchesStored() {
        assertEquals(
                EMAIL_CODE_VERIFIED,
                validationService.validateEmailVerificationCode(
                        Optional.of("123456"), "123456", mock(Session.class), 5));
    }

    @Test
    public void shouldReturnCorrectStateWhenStoredEmailCodeIsEmpty() {
        assertEquals(
                EMAIL_CODE_NOT_VALID,
                validationService.validateEmailVerificationCode(
                        Optional.empty(), "123456", mock(Session.class), 5));
    }

    @Test
    public void
            shouldReturnCorrectStateWhenStoredEmailCodeDoesMatchInputAndRetryLimitHasNotBeenReached() {
        Session session = mock(Session.class);
        when(session.getRetryCount()).thenReturn(1);
        assertEquals(
                EMAIL_CODE_NOT_VALID,
                validationService.validateEmailVerificationCode(
                        Optional.of("654321"), "123456", session, 5));
    }

    @Test
    public void
            shouldReturnCorrectStateWhenStoredEmailCodeDoesMatchInputAndRetryLimitHasBeenReached() {
        Session session = mock(Session.class);
        when(session.getRetryCount()).thenReturn(6);
        assertEquals(
                EMAIL_CODE_MAX_RETRIES_REACHED,
                validationService.validateEmailVerificationCode(
                        Optional.of("654321"), "123456", session, 5));
    }
}
