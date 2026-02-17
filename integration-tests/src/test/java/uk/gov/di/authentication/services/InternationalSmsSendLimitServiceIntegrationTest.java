package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Nested;
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
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.UK_MOBILE_NUMBER;

class InternationalSmsSendLimitServiceIntegrationTest {

    private static final int TEST_SEND_LIMIT = 3;
    private static final String TEST_REFERENCE = "test-reference";

    @RegisterExtension
    protected static final InternationalSmsSendCountExtension extension =
            new InternationalSmsSendCountExtension(TEST_SEND_LIMIT);

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void recordSmsSentShouldFormatPhoneNumberBeforeStoring(String rawPhoneNumber) {
        String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(rawPhoneNumber);

        extension.recordSmsSent(rawPhoneNumber, TEST_REFERENCE);

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

        extension.recordSmsSent(internationalPhoneNumber, TEST_REFERENCE);

        assertTrue(extension.hasRecordForPhoneNumber(formattedPhoneNumber));
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void recordSmsSentShouldIncrementExistingItemIfExists(String internationalPhoneNumber) {
        String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(internationalPhoneNumber);

        extension.recordSmsSent(internationalPhoneNumber, TEST_REFERENCE);
        assertTrue(extension.canSendSms(internationalPhoneNumber));

        for (int i = 0; i < TEST_SEND_LIMIT; i++) {
            extension.recordSmsSent(internationalPhoneNumber, TEST_REFERENCE);
        }

        assertFalse(extension.canSendSms(internationalPhoneNumber));
        assertTrue(extension.hasRecordForPhoneNumber(formattedPhoneNumber));
    }

    @Test
    void differentPhoneNumbersShouldBeTrackedSeparately() {
        String phoneNumber1 = "+33777777001";
        String phoneNumber2 = "+33777777002";

        for (int i = 0; i <= TEST_SEND_LIMIT; i++) {
            extension.recordSmsSent(phoneNumber1, TEST_REFERENCE);
        }

        assertFalse(extension.canSendSms(phoneNumber1));
        assertTrue(extension.canSendSms(phoneNumber2));
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
        extension.recordSmsSent(domesticPhoneNumber, TEST_REFERENCE);
        String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(domesticPhoneNumber);

        assertFalse(
                extension.hasRecordForPhoneNumber(formattedPhoneNumber),
                "Domestic phone numbers should not be stored in the database");
    }

    @Nested
    class WhenExistingInternationalSmsFeatureFlagEnabled {
        @RegisterExtension
        protected static final InternationalSmsSendCountExtension extensionWithFlagEnabled =
                new InternationalSmsSendCountExtension(TEST_SEND_LIMIT, true);

        @Test
        void canSendSmsShouldAllowInternationalNumbersBelowSendLimit() {
            for (int i = 0; i < TEST_SEND_LIMIT - 1; i++) {
                extensionWithFlagEnabled.recordSmsSent(INTERNATIONAL_MOBILE_NUMBER, TEST_REFERENCE);
            }

            boolean canSendSms = extensionWithFlagEnabled.canSendSms(INTERNATIONAL_MOBILE_NUMBER);

            assertTrue(canSendSms);
        }

        @Test
        void canSendSmsShouldBlockInternationalNumbersAtAndAboveSendLimit() {
            for (int i = 0; i < TEST_SEND_LIMIT; i++) {
                extensionWithFlagEnabled.recordSmsSent(INTERNATIONAL_MOBILE_NUMBER, TEST_REFERENCE);
            }

            assertFalse(
                    extensionWithFlagEnabled.canSendSms(INTERNATIONAL_MOBILE_NUMBER),
                    "Should block at send limit");

            extensionWithFlagEnabled.recordSmsSent(INTERNATIONAL_MOBILE_NUMBER, TEST_REFERENCE);

            assertFalse(
                    extensionWithFlagEnabled.canSendSms(INTERNATIONAL_MOBILE_NUMBER),
                    "Should block above send limit");
        }

        @Test
        void canSendSmsShouldAllowDomesticNumbers() {
            boolean canSendSms = extensionWithFlagEnabled.canSendSms(UK_MOBILE_NUMBER);

            assertTrue(canSendSms);
        }

        @Test
        void canSendSmsShouldAllowDomesticNumbersAboveSendLimit() {
            for (int i = 0; i < TEST_SEND_LIMIT + 1; i++) {
                extensionWithFlagEnabled.recordSmsSent(UK_MOBILE_NUMBER, TEST_REFERENCE);
            }

            boolean canSendSms = extensionWithFlagEnabled.canSendSms(UK_MOBILE_NUMBER);

            assertTrue(canSendSms);
        }

        @Test
        void recordSmsSentShouldStillRecordInternationalNumbers() {
            String formattedPhoneNumber =
                    PhoneNumberHelper.formatPhoneNumber(INTERNATIONAL_MOBILE_NUMBER);

            extensionWithFlagEnabled.recordSmsSent(INTERNATIONAL_MOBILE_NUMBER, TEST_REFERENCE);

            assertTrue(extensionWithFlagEnabled.hasRecordForPhoneNumber(formattedPhoneNumber));
        }
    }

    @Nested
    class WhenExistingInternationalSmsFeatureFlagDisabled {
        @RegisterExtension
        protected static final InternationalSmsSendCountExtension extensionWithFlagDisabled =
                new InternationalSmsSendCountExtension(TEST_SEND_LIMIT, false);

        @Test
        void canSendSmsShouldAlwaysBlockInternationalNumbers() {
            for (int i = 0; i <= TEST_SEND_LIMIT + 1; i++) {
                assertFalse(
                        extensionWithFlagDisabled.canSendSms(INTERNATIONAL_MOBILE_NUMBER),
                        "Should block international SMS when feature flag is disabled (after "
                                + i
                                + " records)");
                extensionWithFlagDisabled.recordSmsSent(
                        INTERNATIONAL_MOBILE_NUMBER, TEST_REFERENCE);
            }
        }

        @Test
        void canSendSmsShouldAllowDomesticNumbers() {
            boolean canSendSms = extensionWithFlagDisabled.canSendSms(UK_MOBILE_NUMBER);

            assertTrue(canSendSms);
        }

        @Test
        void canSendSmsShouldAllowDomesticNumbersAboveSendLimit() {
            for (int i = 0; i < TEST_SEND_LIMIT + 1; i++) {
                extensionWithFlagDisabled.recordSmsSent(UK_MOBILE_NUMBER, TEST_REFERENCE);
            }

            boolean canSendSms = extensionWithFlagDisabled.canSendSms(UK_MOBILE_NUMBER);

            assertTrue(canSendSms);
        }

        @Test
        void recordSmsSentShouldStillRecordInternationalNumbers() {
            String formattedPhoneNumber =
                    PhoneNumberHelper.formatPhoneNumber(INTERNATIONAL_MOBILE_NUMBER);

            extensionWithFlagDisabled.recordSmsSent(INTERNATIONAL_MOBILE_NUMBER, TEST_REFERENCE);

            assertTrue(extensionWithFlagDisabled.hasRecordForPhoneNumber(formattedPhoneNumber));
        }
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
