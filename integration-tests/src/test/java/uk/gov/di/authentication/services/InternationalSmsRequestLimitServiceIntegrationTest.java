package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.sharedtest.extensions.InternationalSmsRequestCountExtension;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InternationalSmsRequestLimitServiceIntegrationTest {

    private static final int TEST_REQUEST_LIMIT = 3;

    @RegisterExtension
    protected static final InternationalSmsRequestCountExtension extension =
            new InternationalSmsRequestCountExtension(TEST_REQUEST_LIMIT);

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldAllowFirstRequest(String rawPhoneNumber) {
        boolean canSend = extension.canSendSms(rawPhoneNumber);

        assertTrue(canSend);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldIncrementCountOnEachRequest(String rawPhoneNumber) {
        extension.recordSmsSent(rawPhoneNumber);
        extension.recordSmsSent(rawPhoneNumber);
        extension.recordSmsSent(rawPhoneNumber);

        assertTrue(extension.canSendSms(rawPhoneNumber));
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldFormatPhoneNumberBeforeStoring(String rawPhoneNumber) {
        extension.recordSmsSent(rawPhoneNumber);

        assertTrue(extension.canSendSms(rawPhoneNumber));
    }

    @Test
    void canSendSmsShouldTrackDifferentPhoneNumbersSeparately() {
        String phoneNumber1 = "+33777777001";
        String phoneNumber2 = "+33777777002";

        extension.recordSmsSent(phoneNumber1);
        extension.recordSmsSent(phoneNumber1);
        extension.recordSmsSent(phoneNumber2);

        assertTrue(extension.canSendSms(phoneNumber1));
        assertTrue(extension.canSendSms(phoneNumber2));
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldAllowWhenBelowLimit(String rawPhoneNumber) {
        for (int i = 0; i < TEST_REQUEST_LIMIT; i++) {
            extension.recordSmsSent(rawPhoneNumber);
        }

        boolean canSend = extension.canSendSms(rawPhoneNumber);

        assertTrue(canSend);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldBlockWhenAtLimit(String rawPhoneNumber) {
        for (int i = 0; i < TEST_REQUEST_LIMIT + 1; i++) {
            extension.recordSmsSent(rawPhoneNumber);
        }

        boolean canSend = extension.canSendSms(rawPhoneNumber);

        assertFalse(canSend);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldBlockWhenAboveLimit(String rawPhoneNumber) {
        for (int i = 0; i < TEST_REQUEST_LIMIT + 2; i++) {
            extension.recordSmsSent(rawPhoneNumber);
        }

        boolean canSend = extension.canSendSms(rawPhoneNumber);

        assertFalse(canSend);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldAllowForNewPhoneNumber(String rawPhoneNumber) {
        boolean canSend = extension.canSendSms(rawPhoneNumber);

        assertTrue(canSend);
    }

    @ParameterizedTest
    @MethodSource("domesticPhoneNumberVariations")
    void canSendSmsShouldAllowDomesticNumbers(String domesticPhoneNumber) {
        boolean canSend = extension.canSendSms(domesticPhoneNumber);

        assertTrue(canSend);
    }

    @ParameterizedTest
    @MethodSource("domesticPhoneNumberVariations")
    void recordSmsSentShouldIgnoreDomesticNumbers(String domesticPhoneNumber) {
        extension.recordSmsSent(domesticPhoneNumber);

        boolean canSend = extension.canSendSms(domesticPhoneNumber);

        assertTrue(canSend);
    }

    private static Stream<Arguments> phoneNumberVariations() {
        return Stream.of(
                Arguments.of("+33 777 777 777"),
                Arguments.of("+33777777777"),
                Arguments.of("+49 30 12345678"));
    }

    private static Stream<Arguments> domesticPhoneNumberVariations() {
        return Stream.of(Arguments.of("+44 7700 900000"), Arguments.of("+447700900000"));
    }
}
