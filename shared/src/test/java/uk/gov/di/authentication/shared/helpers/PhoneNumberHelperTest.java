package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PhoneNumberHelperTest {

    private static final String UK_COUNTRY_CODE = "44";

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
    void testShouldReturnTrueForDomesticNumbers(String phoneNumber) {
        assertTrue(PhoneNumberHelper.isDomesticPhoneNumber(phoneNumber));
    }

    @ParameterizedTest
    @MethodSource("internationalPhoneNumbers")
    void testShouldReturnFalseForInternationalNumbers(String phoneNumber) {
        assertFalse(PhoneNumberHelper.isDomesticPhoneNumber(phoneNumber));
    }

    private static Stream<String> domesticPhoneNumbers() {
        return Stream.of("+447316763843", "+447700900000", "+44 7700 900000", "07777777777");
    }

    private static Stream<String> internationalPhoneNumbers() {
        return Stream.of("+33777777777", "+1234567890", "+33645453322");
    }
}
