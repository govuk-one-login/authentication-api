package uk.gov.di.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ErrorResponse;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
}
