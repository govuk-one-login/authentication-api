package uk.gov.di.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ErrorResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ValidationServiceTest {

    private final ValidationService validationService = new ValidationService();

    @Test
    public void shouldRejectEmptyEmail() {
        assertEquals(ErrorResponse.ERROR_1003, validationService.validateEmailAddress("").get());
    }

    @Test
    public void shouldRejectBlankEmail() {
        var spacesEmail = "  ";
        var tabsEmail = "\t\t";
        var newlinesEmail = System.lineSeparator() + System.lineSeparator();

        assertEquals(
                ErrorResponse.ERROR_1003,
                validationService.validateEmailAddress(spacesEmail).get());
        assertEquals(
                ErrorResponse.ERROR_1003, validationService.validateEmailAddress(tabsEmail).get());
        assertEquals(
                ErrorResponse.ERROR_1003,
                validationService.validateEmailAddress(newlinesEmail).get());
    }

    @Test
    public void shouldRejectMalformattedEmail() {
        var noAtsEmail = "test.example.gov.uk";
        var multipleAtsEmail = "test@example@gov.uk";
        var noDotsEmail = "test@examplegovuk";

        assertEquals(
                ErrorResponse.ERROR_1004, validationService.validateEmailAddress(noAtsEmail).get());
        assertEquals(
                ErrorResponse.ERROR_1004,
                validationService.validateEmailAddress(multipleAtsEmail).get());
        assertEquals(
                ErrorResponse.ERROR_1004,
                validationService.validateEmailAddress(noDotsEmail).get());
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
                ErrorResponse.ERROR_1006, validationService.validatePassword(shortPassword).get());
    }

    @Test
    public void shouldRejectEmptyPassword() {
        assertEquals(ErrorResponse.ERROR_1005, validationService.validatePassword("").get());
    }

    @Test
    public void shouldNotThrowNullPointerIfPasswordInputsAreNull() {
        assertEquals(ErrorResponse.ERROR_1005, validationService.validatePassword(null).get());
    }
}
