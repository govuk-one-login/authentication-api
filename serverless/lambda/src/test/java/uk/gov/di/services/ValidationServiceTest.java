package uk.gov.di.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.validation.EmailValidation;
import uk.gov.di.validation.PasswordValidation;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ValidationServiceTest {

    private final ValidationService validationService = new ValidationService();

    @Test
    public void shouldRejectEmptyEmail() {
        assertEquals(
                Set.of(EmailValidation.EMPTY_EMAIL), validationService.validateEmailAddress(""));
    }

    @Test
    public void shouldRejectBlankEmail() {
        var spacesEmail = "  ";
        var tabsEmail = "\t\t";
        var newlinesEmail = System.lineSeparator() + System.lineSeparator();

        assertEquals(
                Set.of(EmailValidation.EMPTY_EMAIL),
                validationService.validateEmailAddress(spacesEmail));
        assertEquals(
                Set.of(EmailValidation.EMPTY_EMAIL),
                validationService.validateEmailAddress(tabsEmail));
        assertEquals(
                Set.of(EmailValidation.EMPTY_EMAIL),
                validationService.validateEmailAddress(newlinesEmail));
    }

    @Test
    public void shouldRejectMalformattedEmail() {
        var noAtsEmail = "test.example.gov.uk";
        var multipleAtsEmail = "test@example@gov.uk";
        var noDotsEmail = "test@examplegovuk";

        assertEquals(
                Set.of(EmailValidation.INCORRECT_FORMAT),
                validationService.validateEmailAddress(noAtsEmail));
        assertEquals(
                Set.of(EmailValidation.INCORRECT_FORMAT),
                validationService.validateEmailAddress(multipleAtsEmail));
        assertEquals(
                Set.of(EmailValidation.INCORRECT_FORMAT),
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
                Set.of(PasswordValidation.PASSWORD_TOO_SHORT),
                validationService.validatePassword(shortPassword));
    }

    @Test
    public void shouldRejectEmptyPassword() {
        assertEquals(
                Set.of(PasswordValidation.EMPTY_PASSWORD_FIELD),
                validationService.validatePassword(""));
    }

    @Test
    public void shouldGiveMultipleErrorsForShortPasswordWithNoNumbers() {
        var shortPasswordWithNoNumbers = "pass";

        assertEquals(
                Set.of(
                        PasswordValidation.NO_NUMBER_INCLUDED,
                        PasswordValidation.PASSWORD_TOO_SHORT),
                validationService.validatePassword(shortPasswordWithNoNumbers));
    }

    @Test
    public void shouldNotThrowNullPointerIfPasswordInputsAreNull() {
        assertEquals(
                Set.of(PasswordValidation.EMPTY_PASSWORD_FIELD),
                validationService.validatePassword(null));
    }
}
