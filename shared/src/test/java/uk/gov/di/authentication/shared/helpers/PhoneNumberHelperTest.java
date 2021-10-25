package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PhoneNumberHelperTest {

    @Test
    public void testShouldFormatPhoneNumbersUsingE164() {
        final String phoneNumber = "07316763843";

        final String result = PhoneNumberHelper.formatPhoneNumber(phoneNumber);

        assertEquals("+447316763843", result);
    }

    @Test
    public void testShouldThrowExceptionIfInvalidPhoneNumber() {
        final String phoneNumber = "Invalid phone number";

        assertThrows(
                RuntimeException.class,
                () -> PhoneNumberHelper.formatPhoneNumber(phoneNumber),
                "Expected to throw exception");
    }
}
