package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PhoneNumberHelperTest {

    @Test
    void testShouldFormatPhoneNumbersUsingE164() {
        final String phoneNumber = "07316763843";

        final String result = PhoneNumberHelper.formatPhoneNumber(phoneNumber);

        assertEquals("+447316763843", result);
    }

    @Test
    void testShouldThrowExceptionIfInvalidPhoneNumber() {
        final String phoneNumber = "Invalid phone number";

        assertThrows(
                RuntimeException.class,
                () -> PhoneNumberHelper.formatPhoneNumber(phoneNumber),
                "Expected to throw exception");
    }

    @ParameterizedTest
    @MethodSource("domesticPhoneNumbers")
    void isDomesticPhoneNumberShouldReturnTrueForDomesticNumbers(String phoneNumber) {
        assertTrue(PhoneNumberHelper.isDomesticPhoneNumber(phoneNumber));
    }

    @ParameterizedTest
    @MethodSource("internationalPhoneNumbers")
    void isDomesticPhoneNumberShouldReturnFalseForInternationalNumbers(String phoneNumber) {
        assertFalse(PhoneNumberHelper.isDomesticPhoneNumber(phoneNumber));
    }

    @Test
    void isDomesticPhoneNumberShouldDefaultToFalse() {
        assertFalse(PhoneNumberHelper.isDomesticPhoneNumber("invalid"));
    }

    private static Stream<String> domesticPhoneNumbers() {
        return Stream.of(
                "+447316763843", "+447700900000", "+44 7700 900000", "07777777777", "07123 456789");
    }

    private static Stream<String> internationalPhoneNumbers() {
        return Stream.of("+33777777777", "+1234567890", "+33645453322");
    }
}
