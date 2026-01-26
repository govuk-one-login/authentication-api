package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.sharedtest.extensions.InternationalSmsSendCountExtension;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InternationalSmsSendLimitServiceIntegrationTest {

    private static final int TEST_SEND_LIMIT = 3;

    @RegisterExtension
    protected static final InternationalSmsSendCountExtension extension =
            new InternationalSmsSendCountExtension(TEST_SEND_LIMIT);

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void recordSmsSentShouldFormatPhoneNumberBeforeStoring(String rawPhoneNumber) {
        String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(rawPhoneNumber);

        extension.recordSmsSent(rawPhoneNumber);

        assertTrue(extension.hasRecordForPhoneNumber(formattedPhoneNumber));
        if (!rawPhoneNumber.equals(formattedPhoneNumber)) {
            assertFalse(extension.hasRecordForPhoneNumber(rawPhoneNumber));
        }
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void recordSmsSentShouldCreateNewItemIfNotExists(String internationalPhoneNumber) {
        String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(internationalPhoneNumber);

        assertFalse(extension.hasRecordForPhoneNumber(formattedPhoneNumber));

        extension.recordSmsSent(internationalPhoneNumber);

        assertTrue(extension.hasRecordForPhoneNumber(formattedPhoneNumber));
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void recordSmsSentShouldIncrementExistingItemIfExists(String internationalPhoneNumber) {
        String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(internationalPhoneNumber);

        extension.recordSmsSent(internationalPhoneNumber);
        assertTrue(extension.canSendSms(internationalPhoneNumber));

        for (int i = 0; i < TEST_SEND_LIMIT; i++) {
            extension.recordSmsSent(internationalPhoneNumber);
        }

        assertFalse(extension.canSendSms(internationalPhoneNumber));
        assertTrue(extension.hasRecordForPhoneNumber(formattedPhoneNumber));
    }

    @Test
    void differentPhoneNumbersShouldBeTrackedSeparately() {
        String phoneNumber1 = "+33777777001";
        String phoneNumber2 = "+33777777002";

        for (int i = 0; i <= TEST_SEND_LIMIT; i++) {
            extension.recordSmsSent(phoneNumber1);
        }

        assertFalse(extension.canSendSms(phoneNumber1));
        assertTrue(extension.canSendSms(phoneNumber2));
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldAllowForNewPhoneNumber(String rawPhoneNumber) {
        boolean canSend = extension.canSendSms(rawPhoneNumber);

        assertTrue(canSend);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldAllowWhenBelowLimit(String rawPhoneNumber) {
        for (int i = 0; i < TEST_SEND_LIMIT - 1; i++) {
            extension.recordSmsSent(rawPhoneNumber);
        }

        boolean canSend = extension.canSendSms(rawPhoneNumber);

        assertTrue(canSend);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldBlockWhenAtLimit(String rawPhoneNumber) {
        for (int i = 0; i < TEST_SEND_LIMIT; i++) {
            extension.recordSmsSent(rawPhoneNumber);
        }

        boolean canSend = extension.canSendSms(rawPhoneNumber);

        assertFalse(canSend);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldBlockWhenAboveLimit(String rawPhoneNumber) {
        for (int i = 0; i < TEST_SEND_LIMIT + 1; i++) {
            extension.recordSmsSent(rawPhoneNumber);
        }

        boolean canSend = extension.canSendSms(rawPhoneNumber);

        assertFalse(canSend);
    }

    @ParameterizedTest
    @MethodSource("domesticPhoneNumberVariations")
    void canSendSmsShouldAllowDomesticNumbers(String domesticPhoneNumber) {
        boolean canSend = extension.canSendSms(domesticPhoneNumber);

        assertTrue(canSend);
    }

    @ParameterizedTest
    @MethodSource("domesticPhoneNumberVariations")
    void canSendSmsShouldAlwaysAllowDomesticNumbersRegardlessOfLimit(String domesticPhoneNumber) {
        for (int i = 0; i < TEST_SEND_LIMIT + 5; i++) {
            extension.recordSmsSent(domesticPhoneNumber);
        }

        assertTrue(extension.canSendSms(domesticPhoneNumber));
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void canSendSmsShouldNotCreateRecord(String internationalPhoneNumber) {
        String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(internationalPhoneNumber);

        extension.canSendSms(internationalPhoneNumber);

        assertFalse(extension.hasRecordForPhoneNumber(formattedPhoneNumber));
    }

    @ParameterizedTest
    @MethodSource("domesticPhoneNumberVariations")
    void recordSmsSentShouldIgnoreDomesticNumbers(String domesticPhoneNumber) {
        extension.recordSmsSent(domesticPhoneNumber);
        String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(domesticPhoneNumber);

        assertFalse(
                extension.hasRecordForPhoneNumber(formattedPhoneNumber),
                "Domestic phone numbers should not be stored in the database");
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
