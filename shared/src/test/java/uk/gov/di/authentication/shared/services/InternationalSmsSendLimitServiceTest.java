package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.authentication.shared.entity.InternationalSmsSendCount;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InternationalSmsSendLimitServiceTest {

    private static final int TEST_SEND_LIMIT = 3;
    private final DynamoDbTable<InternationalSmsSendCount> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private InternationalSmsSendLimitService service;

    @BeforeEach
    void setUp() {
        when(configurationService.getInternationalSmsNumberSendLimit()).thenReturn(TEST_SEND_LIMIT);
        service = new InternationalSmsSendLimitService(dynamoDbClient, table, configurationService);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void hasReachedInternationalSmsLimitShouldAllowFirstRequest(String rawPhoneNumber) {
        withNoItem();

        boolean canSend = service.hasReachedInternationalSmsLimit(rawPhoneNumber);

        assertTrue(canSend);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void recordSmsSentShouldCreateRecordForFirstRequest(
            String rawPhoneNumber, String formattedPhoneNumber) {
        withNoItem();
        ArgumentCaptor<InternationalSmsSendCount> captor =
                ArgumentCaptor.forClass(InternationalSmsSendCount.class);

        service.recordSmsSent(rawPhoneNumber);

        verify(table).putItem(captor.capture());
        assertEquals(formattedPhoneNumber, captor.getValue().getPhoneNumber());
        assertEquals(1, captor.getValue().getSentCount());
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void recordSmsSentShouldIncrementExistingCount(
            String rawPhoneNumber, String formattedPhoneNumber) {
        withExistingCount(2, formattedPhoneNumber);
        ArgumentCaptor<InternationalSmsSendCount> captor =
                ArgumentCaptor.forClass(InternationalSmsSendCount.class);

        service.recordSmsSent(rawPhoneNumber);

        verify(table).updateItem(captor.capture());
        assertEquals(formattedPhoneNumber, captor.getValue().getPhoneNumber());
        assertEquals(3, captor.getValue().getSentCount());
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void hasReachedInternationalSmsLimitShouldAllowWhenBelowLimit(
            String rawPhoneNumber, String formattedPhoneNumber) {
        withExistingCount(TEST_SEND_LIMIT - 1, formattedPhoneNumber);

        boolean canSend = service.hasReachedInternationalSmsLimit(rawPhoneNumber);

        assertTrue(canSend);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void hasReachedInternationalSmsLimitShouldBlockWhenAtLimit(
            String rawPhoneNumber, String formattedPhoneNumber) {
        withExistingCount(TEST_SEND_LIMIT, formattedPhoneNumber);

        boolean canSend = service.hasReachedInternationalSmsLimit(rawPhoneNumber);

        assertFalse(canSend);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void hasReachedInternationalSmsLimitShouldBlockWhenAboveLimit(
            String rawPhoneNumber, String formattedPhoneNumber) {
        withExistingCount(TEST_SEND_LIMIT + 1, formattedPhoneNumber);

        boolean canSend = service.hasReachedInternationalSmsLimit(rawPhoneNumber);

        assertFalse(canSend);
    }

    @ParameterizedTest
    @MethodSource("domesticPhoneNumberVariations")
    void hasReachedInternationalSmsLimitShouldAllowDomesticNumbers(String domesticPhoneNumber) {
        boolean canSend = service.hasReachedInternationalSmsLimit(domesticPhoneNumber);

        assertTrue(canSend);
    }

    @ParameterizedTest
    @MethodSource("domesticPhoneNumberVariations")
    void recordSmsSentShouldIgnoreDomesticNumbers(String domesticPhoneNumber) {
        service.recordSmsSent(domesticPhoneNumber);

        verify(table, never()).putItem(any(InternationalSmsSendCount.class));
        verify(table, never()).updateItem(any(InternationalSmsSendCount.class));
    }

    @ParameterizedTest
    @MethodSource("phoneNumberVariations")
    void hasReachedInternationalSmsLimitShouldUseFormattedPhoneNumber(
            String rawPhoneNumber, String formattedPhoneNumber) {
        withExistingCount(TEST_SEND_LIMIT, formattedPhoneNumber);

        boolean canSend = service.hasReachedInternationalSmsLimit(rawPhoneNumber);

        assertFalse(canSend);
        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);
        verify(table).getItem(keyCaptor.capture());
    }

    @ParameterizedTest
    @MethodSource("domesticPhoneNumberVariations")
    void hasReachedInternationalSmsLimitShouldAllowDomesticNumbersEvenWhenAboveLimit(
            String domesticPhoneNumber) {
        String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(domesticPhoneNumber);
        withExistingCount(TEST_SEND_LIMIT + 5, formattedPhoneNumber);

        boolean canSend = service.hasReachedInternationalSmsLimit(domesticPhoneNumber);

        assertTrue(canSend);
    }

    @Test
    void hasReachedInternationalSmsLimitShouldNotQueryDatabaseForDomesticNumbers() {
        String domesticPhoneNumber = "+447700900000";

        service.hasReachedInternationalSmsLimit(domesticPhoneNumber);

        verify(table, never()).getItem(any(Key.class));
    }

    private static Stream<Arguments> phoneNumberVariations() {
        return Stream.of(
                Arguments.of("+33 777 777 777", "+33777777777"),
                Arguments.of("+33777777777", "+33777777777"));
    }

    private static Stream<Arguments> domesticPhoneNumberVariations() {
        return Stream.of(Arguments.of("+44 7700 900000"), Arguments.of("+447700900000"));
    }

    private void withNoItem() {
        when(table.getItem(any(Key.class))).thenReturn(null);
    }

    private void withExistingCount(int count, String formattedPhoneNumber) {
        InternationalSmsSendCount record =
                new InternationalSmsSendCount()
                        .withPhoneNumber(formattedPhoneNumber)
                        .withSentCount(count);
        when(table.getItem(any(Key.class))).thenReturn(record);
    }
}
