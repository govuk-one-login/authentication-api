package uk.gov.di.authentication.utils.lambda;

import org.apache.logging.log4j.Level;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemResponse;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;
import uk.gov.di.authentication.sharedtest.logging.LogEventMatcher;
import uk.gov.di.authentication.utils.entity.LastSignedInBackfillRequest;
import uk.gov.di.authentication.utils.helpers.LastSignedInBackfillHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LastSignedInBackfillHandlerTest {

    private static final String ENVIRONMENT = "test";
    private static final String TRACKER_TABLE = "test-tracker-table";
    private static final String LAMBDA_NAME = "test-last-signed-in-backfill-lambda";
    private static final String TRACKER_TIMESTAMP = "2026-01-01T00:00:00.000Z";

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDbClient client = mock(DynamoDbClient.class);
    private final LambdaInvokerService lambdaInvokerService = mock(LambdaInvokerService.class);
    private final Json objectMapper = SerializationService.getInstance();

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(LastSignedInBackfillHandler.class);

    @RegisterExtension
    public final CaptureLoggingExtension helperLogging =
            new CaptureLoggingExtension(LastSignedInBackfillHelper.class);

    @BeforeEach
    void setUp() {
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);
        when(configurationService.getLastSignedInBackfillParallelism()).thenReturn(4);
        when(configurationService.getLastSignedInBackfillTotalSegments()).thenReturn(1);
        when(configurationService.getLastSignedInBackfillMaxItemsPerSegment()).thenReturn(100000);
        when(configurationService.getLastSignedInBackfillLambdaName()).thenReturn(LAMBDA_NAME);
        when(configurationService.getLastSignedInBackfillPauseBetweenInvocationsMs())
                .thenReturn(0L);
        when(configurationService.getLastSignedInBackfillTrackerTableName())
                .thenReturn(TRACKER_TABLE);
        when(configurationService.getLastSignedInBackfillMaxInvocations()).thenReturn(1000);
        when(client.updateItem(any(UpdateItemRequest.class)))
                .thenReturn(UpdateItemResponse.builder().build());
    }

    private LastSignedInBackfillHandler createHandler() {
        return new LastSignedInBackfillHandler(configurationService, client, lambdaInvokerService);
    }

    @Test
    void shouldHandleNullRequest() {
        mockScanWithItems(List.of());

        var response = createHandler().handleRequest(null);

        assertEquals(0, response.processedCount());
        assertEquals(0, response.updatedCount());
        assertEquals(0, response.skippedCount());
    }

    @Test
    void shouldUpdateUserProfileForEachTrackerItemWithValidFields() {
        int itemCount = 5;
        mockScanWithItems(createTrackerItems(itemCount));

        var response =
                createHandler()
                        .handleRequest(
                                new LastSignedInBackfillRequest(null, null, null, null, null));

        assertEquals(itemCount, response.processedCount());
        assertEquals(itemCount, response.updatedCount());
        assertEquals(0, response.skippedCount());
        verify(client, times(itemCount)).updateItem(any(UpdateItemRequest.class));
    }

    @Test
    void shouldSkipTrackerItemsMissingEmailAddress() {
        List<Map<String, AttributeValue>> items = new ArrayList<>();
        items.add(
                Map.of(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_USER_LAST_ACTIVE,
                        AttributeValue.fromS(TRACKER_TIMESTAMP)));
        mockScanWithItems(items);

        var response =
                createHandler()
                        .handleRequest(
                                new LastSignedInBackfillRequest(null, null, null, null, null));

        assertEquals(1, response.processedCount());
        assertEquals(0, response.updatedCount());
        assertEquals(1, response.skippedCount());
        verify(client, never()).updateItem(any(UpdateItemRequest.class));
    }

    @Test
    void shouldSkipTrackerItemsMissingUserLastActive() {
        List<Map<String, AttributeValue>> items = new ArrayList<>();
        items.add(
                Map.of(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_EMAIL,
                        AttributeValue.fromS("user@example.com")));
        mockScanWithItems(items);

        var response =
                createHandler()
                        .handleRequest(
                                new LastSignedInBackfillRequest(null, null, null, null, null));

        assertEquals(1, response.processedCount());
        assertEquals(0, response.updatedCount());
        assertEquals(1, response.skippedCount());
        verify(client, never()).updateItem(any(UpdateItemRequest.class));
    }

    @Test
    void shouldSkipTrackerItemsWithBlankUserLastActive() {
        List<Map<String, AttributeValue>> items = new ArrayList<>();
        items.add(
                Map.of(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_EMAIL,
                        AttributeValue.fromS("user@example.com"),
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_USER_LAST_ACTIVE,
                        AttributeValue.fromS("   ")));
        mockScanWithItems(items);

        var response =
                createHandler()
                        .handleRequest(
                                new LastSignedInBackfillRequest(null, null, null, null, null));

        assertEquals(0, response.updatedCount());
        assertEquals(1, response.skippedCount());
    }

    @Test
    void shouldLogWarnWhenTrackerItemMissingEmailAddress() {
        List<Map<String, AttributeValue>> items = new ArrayList<>();
        items.add(
                Map.of(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_USER_LAST_ACTIVE,
                        AttributeValue.fromS(TRACKER_TIMESTAMP)));
        mockScanWithItems(items);

        createHandler()
                .handleRequest(new LastSignedInBackfillRequest(null, null, null, null, null));

        assertThat(
                helperLogging.events(),
                hasItem(
                        LogEventMatcher.withLevelAndMessageContaining(
                                Level.WARN, "email=absent", "userLastActive=present")));
    }

    @Test
    void shouldLogWarnWhenTrackerItemMissingUserLastActive() {
        List<Map<String, AttributeValue>> items = new ArrayList<>();
        items.add(
                Map.of(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_EMAIL,
                        AttributeValue.fromS("user@example.com")));
        mockScanWithItems(items);

        createHandler()
                .handleRequest(new LastSignedInBackfillRequest(null, null, null, null, null));

        assertThat(
                helperLogging.events(),
                hasItem(
                        LogEventMatcher.withLevelAndMessageContaining(
                                Level.WARN, "email=present", "userLastActive=absent")));
    }

    @Test
    void shouldLogWarnWhenTrackerItemHasBlankUserLastActive() {
        List<Map<String, AttributeValue>> items = new ArrayList<>();
        items.add(
                Map.of(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_EMAIL,
                        AttributeValue.fromS("user@example.com"),
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_USER_LAST_ACTIVE,
                        AttributeValue.fromS("   ")));
        mockScanWithItems(items);

        createHandler()
                .handleRequest(new LastSignedInBackfillRequest(null, null, null, null, null));

        assertThat(
                helperLogging.events(),
                hasItem(
                        LogEventMatcher.withLevelAndMessageContaining(
                                Level.WARN, "email=present", "userLastActive=present")));
    }

    @Test
    void shouldNotLogWarnForConditionalCheckFailedException() {
        mockScanWithItems(createTrackerItems(1));
        when(client.updateItem(any(UpdateItemRequest.class)))
                .thenThrow(
                        ConditionalCheckFailedException.builder()
                                .message("already up to date")
                                .build());

        createHandler()
                .handleRequest(new LastSignedInBackfillRequest(null, null, null, null, null));

        assertThat(
                helperLogging.events(),
                not(hasItem(LogEventMatcher.withLevelAndMessageContaining(Level.WARN, "absent"))));
    }

    @Test
    void shouldTreatConditionalCheckFailedExceptionAsSkip() {
        mockScanWithItems(createTrackerItems(3));
        when(client.updateItem(any(UpdateItemRequest.class)))
                .thenThrow(
                        ConditionalCheckFailedException.builder()
                                .message("already up to date")
                                .build());

        var response =
                createHandler()
                        .handleRequest(
                                new LastSignedInBackfillRequest(null, null, null, null, null));

        assertEquals(3, response.processedCount());
        assertEquals(0, response.updatedCount());
        assertEquals(3, response.skippedCount());
    }

    @Test
    void shouldWriteCorrectTimestampToUserProfileUpdateItem() {
        mockScanWithItems(createTrackerItems(1));

        createHandler()
                .handleRequest(new LastSignedInBackfillRequest(null, null, null, null, null));

        var captor = ArgumentCaptor.forClass(UpdateItemRequest.class);
        verify(client).updateItem(captor.capture());
        assertEquals(
                TRACKER_TIMESTAMP,
                captor.getValue().expressionAttributeValues().get(":trackerTimestamp").s());
    }

    @Test
    void shouldAccumulateCountsFromPreviousInvocations() {
        mockScanWithItems(createTrackerItems(5));

        var response =
                createHandler()
                        .handleRequest(
                                new LastSignedInBackfillRequest(null, 500L, 200L, 100L, null));

        assertEquals(505L, response.processedCount());
        assertEquals(205L, response.updatedCount());
        assertEquals(100L, response.skippedCount());
    }

    @Test
    void shouldPassCorrectContinuationStateInSelfInvocation() {
        when(configurationService.getLastSignedInBackfillMaxItemsPerSegment()).thenReturn(5);
        mockScanWithPagination(25, 5);

        createHandler().handleRequest(new LastSignedInBackfillRequest(null, 100L, 50L, 10L, 3L));

        var payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(lambdaInvokerService)
                .invokeAsyncWithPayload(payloadCaptor.capture(), eq(LAMBDA_NAME));

        var continuation =
                objectMapper.readValueUnchecked(
                        payloadCaptor.getValue(), LastSignedInBackfillRequest.class);

        assertNotNull(continuation.segmentKeys());
        assertEquals(105L, continuation.processedCount());
        assertEquals(4L, continuation.invocationCount());
        // updatedCount and skippedCount should be carried through
        assertNotNull(continuation.updatedCount());
        assertNotNull(continuation.skippedCount());
    }

    @Test
    void shouldIncrementInvocationCountFromNullOnFirstSelfInvoke() {
        when(configurationService.getLastSignedInBackfillMaxItemsPerSegment()).thenReturn(5);
        mockScanWithPagination(25, 5);

        createHandler()
                .handleRequest(new LastSignedInBackfillRequest(null, null, null, null, null));

        var payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(lambdaInvokerService)
                .invokeAsyncWithPayload(payloadCaptor.capture(), eq(LAMBDA_NAME));

        var continuation =
                objectMapper.readValueUnchecked(
                        payloadCaptor.getValue(), LastSignedInBackfillRequest.class);

        assertEquals(1L, continuation.invocationCount());
    }

    @Test
    void shouldReturnLastEvaluatedKeyWhenItemLimitStopsSegmentEarly() {
        mockScanWithPagination(25, 5);

        var result = createHandler().scanSegment(0, 1, 5, null);

        assertEquals(5, result.itemsScanned());
        assertNotNull(result.lastEvaluatedKey());
    }

    @Test
    void shouldReturnNullLastEvaluatedKeyWhenSegmentFullyExhausted() {
        mockScanWithItems(createTrackerItems(5));

        var result = createHandler().scanSegment(0, 1, 7500, null);

        assertEquals(5, result.itemsScanned());
        assertNull(result.lastEvaluatedKey());
    }

    @Test
    void shouldPropagateExceptionWhenScanFails() {
        when(client.scan(any(ScanRequest.class))).thenThrow(new RuntimeException("DynamoDB error"));

        assertThrows(RuntimeException.class, () -> createHandler().scanSegment(0, 1, 100, null));
    }

    @Test
    void shouldSerialiseAndDeserialiseRequestRoundTrip() throws Exception {
        var request =
                new LastSignedInBackfillRequest(
                        Map.of(
                                0,
                                Map.of(
                                        "dateForDeletion",
                                        "2031-06-01",
                                        "commonSubjectId",
                                        "urn:fdc:gov.uk:2022:test")),
                        100L,
                        50L,
                        20L,
                        2L);

        String json = objectMapper.writeValueAsString(request);
        var deserialised = objectMapper.readValueUnchecked(json, LastSignedInBackfillRequest.class);

        assertEquals(request.processedCount(), deserialised.processedCount());
        assertEquals(request.updatedCount(), deserialised.updatedCount());
        assertEquals(request.skippedCount(), deserialised.skippedCount());
        assertEquals(request.invocationCount(), deserialised.invocationCount());
        assertEquals("2031-06-01", deserialised.segmentKeys().get(0).get("dateForDeletion"));
        assertEquals(
                "urn:fdc:gov.uk:2022:test",
                deserialised.segmentKeys().get(0).get("commonSubjectId"));
    }

    @Test
    void shouldDeserialiseEmptyPayloadAsFirstInvocation() {
        var deserialised = objectMapper.readValueUnchecked("{}", LastSignedInBackfillRequest.class);

        assertNull(deserialised.segmentKeys());
        assertNull(deserialised.processedCount());
        assertNull(deserialised.updatedCount());
        assertNull(deserialised.skippedCount());
        assertNull(deserialised.invocationCount());
    }

    private List<Map<String, AttributeValue>> createTrackerItems(int count) {
        List<Map<String, AttributeValue>> items = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            items.add(
                    Map.of(
                            LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_EMAIL,
                            AttributeValue.fromS("user" + i + "@example.com"),
                            LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_USER_LAST_ACTIVE,
                            AttributeValue.fromS(TRACKER_TIMESTAMP)));
        }
        return items;
    }

    private void mockScanWithItems(List<Map<String, AttributeValue>> items) {
        when(client.scan(any(ScanRequest.class)))
                .thenReturn(
                        ScanResponse.builder()
                                .items(items)
                                .count(items.size())
                                .scannedCount(items.size())
                                .build());
    }

    private void mockScanWithPagination(int totalItems, int pageSize) {
        List<Map<String, AttributeValue>> allItems = createTrackerItems(totalItems);
        List<ScanResponse> pages = new ArrayList<>();

        for (int start = 0; start < totalItems; start += pageSize) {
            int end = Math.min(start + pageSize, totalItems);
            List<Map<String, AttributeValue>> pageItems = allItems.subList(start, end);
            boolean hasMore = end < totalItems;

            ScanResponse.Builder builder =
                    ScanResponse.builder()
                            .items(pageItems)
                            .count(pageItems.size())
                            .scannedCount(pageItems.size());

            if (hasMore) {
                builder.lastEvaluatedKey(
                        Map.of(
                                "dateForDeletion",
                                AttributeValue.fromS("2031-06-01"),
                                "commonSubjectId",
                                AttributeValue.fromS("urn:fdc:gov.uk:2022:key-" + end)));
            }
            pages.add(builder.build());
        }

        AtomicInteger callCount = new AtomicInteger(0);
        when(client.scan(any(ScanRequest.class)))
                .thenAnswer(invocation -> pages.get(callCount.getAndIncrement()));
    }
}
