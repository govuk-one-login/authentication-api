package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.utils.entity.InactiveAccountDataExportRequest;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InactiveAccountDataExportHandlerTest {

    private static final TableSchema<UserProfile> USER_PROFILE_SCHEMA =
            TableSchema.fromBean(UserProfile.class);
    private static final String ENVIRONMENT = "test";
    private static final String USER_CREDENTIALS_TABLE = ENVIRONMENT + "-user-credentials";

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDbClient client = mock(DynamoDbClient.class);
    private final Context context = mock(Context.class);

    @BeforeEach
    void setUp() {
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);
        when(configurationService.getInactiveAccountExportParallelism()).thenReturn(4);
        when(configurationService.getInactiveAccountExportTotalSegments()).thenReturn(1);
        when(configurationService.getInactiveAccountExportMaxRetries()).thenReturn(3);
        when(configurationService.getInactiveAccountExportMaxItemsPerSegment()).thenReturn(7500);
    }

    private InactiveAccountDataExportHandler createHandler() {
        return new InactiveAccountDataExportHandler(configurationService, client);
    }

    @Test
    void shouldHandleNullRequest() {
        mockScanWithPagination(0, 1);

        var handler = createHandler();
        var response = handler.handleRequest(null, context);

        assertEquals(0, response.processedCount());
        assertEquals(0, response.writtenCount());
    }

    @Test
    void shouldHandleEmptyRequest() {
        int itemCount = 5;
        mockScanWithPagination(itemCount, itemCount);
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, null, null);

        var response = handler.handleRequest(request, context);

        assertEquals(itemCount, response.processedCount());
        assertEquals(0, response.writtenCount());
    }

    @Test
    void shouldPaginateThroughAllPagesInSegment() {
        int itemCount = 25;
        int pageSize = 5;
        mockScanWithPagination(itemCount, pageSize);
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, null, null);

        var response = handler.handleRequest(request, context);

        assertEquals(itemCount, response.processedCount());
    }

    @Test
    void shouldLogErrorAndPropagateExceptionWhenScanFails() {
        when(client.scan(any(ScanRequest.class)))
                .thenThrow(
                        DynamoDbException.builder()
                                .message("Provisioned throughput exceeded")
                                .build());

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, null, null);

        assertThrows(DynamoDbException.class, () -> handler.handleRequest(request, context));
    }

    @Test
    void shouldJoinAllItemsWhenAllCredentialsExist() {
        int itemCount = 5;
        mockScanWithPagination(itemCount, itemCount);
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, null, null);

        var response = handler.handleRequest(request, context);

        assertEquals(itemCount, response.processedCount());
        verify(client, times(1)).batchGetItem(any(BatchGetItemRequest.class));
    }

    @Test
    void shouldRetryUnprocessedKeysSuccessfully() {
        int itemCount = 5;
        mockScanWithPagination(itemCount, itemCount);

        AtomicInteger batchCallCount = new AtomicInteger(0);
        when(client.batchGetItem(any(BatchGetItemRequest.class)))
                .thenAnswer(
                        invocation -> {
                            BatchGetItemRequest request = invocation.getArgument(0);
                            KeysAndAttributes keysAndAttrs =
                                    request.requestItems().get(USER_CREDENTIALS_TABLE);
                            List<Map<String, AttributeValue>> keys = keysAndAttrs.keys();
                            int call = batchCallCount.getAndIncrement();

                            if (call == 0) {
                                // First call: return 3 items, leave 2 unprocessed
                                List<Map<String, AttributeValue>> results = new ArrayList<>();
                                for (int i = 0; i < 3; i++) {
                                    String email = keys.get(i).get("Email").s();
                                    results.add(createCredentialItem(email));
                                }
                                Map<String, KeysAndAttributes> unprocessed =
                                        Map.of(
                                                USER_CREDENTIALS_TABLE,
                                                KeysAndAttributes.builder()
                                                        .keys(keys.subList(3, 5))
                                                        .projectionExpression(
                                                                "Email,Created,Updated,MigratedPassword")
                                                        .build());
                                return BatchGetItemResponse.builder()
                                        .responses(Map.of(USER_CREDENTIALS_TABLE, results))
                                        .unprocessedKeys(unprocessed)
                                        .build();
                            } else {
                                // Second call: return remaining items
                                List<Map<String, AttributeValue>> results = new ArrayList<>();
                                for (Map<String, AttributeValue> key : keys) {
                                    String email = key.get("Email").s();
                                    results.add(createCredentialItem(email));
                                }
                                return BatchGetItemResponse.builder()
                                        .responses(Map.of(USER_CREDENTIALS_TABLE, results))
                                        .build();
                            }
                        });

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, null, null);

        var response = handler.handleRequest(request, context);

        assertEquals(itemCount, response.processedCount());
        verify(client, times(2)).batchGetItem(any(BatchGetItemRequest.class));
    }

    @Test
    void shouldCountUnprocessedKeysAsMissingAfterRetriesExhausted() {
        int itemCount = 5;
        mockScanWithPagination(itemCount, itemCount);

        when(configurationService.getInactiveAccountExportMaxRetries()).thenReturn(2);

        // Always return unprocessed keys for items 4 and 5
        when(client.batchGetItem(any(BatchGetItemRequest.class)))
                .thenAnswer(
                        invocation -> {
                            BatchGetItemRequest request = invocation.getArgument(0);
                            KeysAndAttributes keysAndAttrs =
                                    request.requestItems().get(USER_CREDENTIALS_TABLE);
                            List<Map<String, AttributeValue>> keys = keysAndAttrs.keys();

                            List<Map<String, AttributeValue>> results = new ArrayList<>();
                            List<Map<String, AttributeValue>> unprocessedKeys = new ArrayList<>();

                            for (int i = 0; i < keys.size(); i++) {
                                String email = keys.get(i).get("Email").s();
                                if (email.startsWith("user4") || email.startsWith("user5")) {
                                    unprocessedKeys.add(keys.get(i));
                                } else {
                                    results.add(createCredentialItem(email));
                                }
                            }

                            BatchGetItemResponse.Builder responseBuilder =
                                    BatchGetItemResponse.builder()
                                            .responses(Map.of(USER_CREDENTIALS_TABLE, results));

                            if (!unprocessedKeys.isEmpty()) {
                                responseBuilder.unprocessedKeys(
                                        Map.of(
                                                USER_CREDENTIALS_TABLE,
                                                KeysAndAttributes.builder()
                                                        .keys(unprocessedKeys)
                                                        .projectionExpression(
                                                                "Email,Created,Updated,MigratedPassword")
                                                        .build()));
                            }

                            return responseBuilder.build();
                        });

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, null, null);

        var response = handler.handleRequest(request, context);

        assertEquals(itemCount, response.processedCount());
        // Initial call + 2 retries = 3 calls
        verify(client, times(3)).batchGetItem(any(BatchGetItemRequest.class));
    }

    @Test
    void shouldNotCallBatchGetItemWhenSegmentIsEmpty() {
        mockScanWithPagination(0, 1);

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, null, null);

        var response = handler.handleRequest(request, context);

        assertEquals(0, response.processedCount());
        verify(client, never()).batchGetItem(any(BatchGetItemRequest.class));
    }

    @Test
    void shouldBatchAtExactly100Items() {
        int itemCount = 100;
        mockScanWithPagination(itemCount, itemCount);
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, null, null);

        var response = handler.handleRequest(request, context);

        assertEquals(itemCount, response.processedCount());
        verify(client, times(1)).batchGetItem(any(BatchGetItemRequest.class));
    }

    @Test
    void shouldSplitIntoMultipleBatchesWhenOver100Items() {
        int itemCount = 101;
        mockScanWithPagination(itemCount, itemCount);
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, null, null);

        var response = handler.handleRequest(request, context);

        assertEquals(itemCount, response.processedCount());
        // 101 items = batch of 100 + final batch of 1 = 2 calls
        verify(client, times(2)).batchGetItem(any(BatchGetItemRequest.class));
    }

    @Test
    void shouldAccumulateItemsAcrossPagesBeforeBatching() {
        int itemCount = 25;
        int pageSize = 5;
        mockScanWithPagination(itemCount, pageSize);
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, null, null);

        var response = handler.handleRequest(request, context);

        assertEquals(itemCount, response.processedCount());
        // 25 items < 100 so only final partial batch = 1 call
        verify(client, times(1)).batchGetItem(any(BatchGetItemRequest.class));
    }

    @Test
    void shouldStopScanningSegmentWhenItemLimitReached() {
        when(configurationService.getInactiveAccountExportMaxItemsPerSegment()).thenReturn(10);
        int totalItems = 25;
        int pageSize = 5;
        mockScanWithPagination(totalItems, pageSize);
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, null, null);

        var response = handler.handleRequest(request, context);

        assertEquals(10, response.processedCount());
    }

    @Test
    void shouldReturnLastEvaluatedKeyWhenItemLimitStopsSegmentEarly() {
        when(configurationService.getInactiveAccountExportMaxItemsPerSegment()).thenReturn(5);
        int totalItems = 25;
        int pageSize = 5;
        mockScanWithPagination(totalItems, pageSize);
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();

        var result = handler.scanSegment(0, 1, 3, 5, null);

        assertEquals(5, result.itemsScanned());
        assertNotNull(result.lastEvaluatedKey());
    }

    @Test
    void shouldReturnNullLastEvaluatedKeyWhenSegmentFullyExhausted() {
        int totalItems = 5;
        mockScanWithPagination(totalItems, totalItems);
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();

        var result = handler.scanSegment(0, 1, 3, 7500, null);

        assertEquals(5, result.itemsScanned());
        assertNull(result.lastEvaluatedKey());
    }

    @Test
    void shouldResumeFromStartKeyWhenProvided() {
        int totalItems = 10;
        int pageSize = 5;
        List<ScanResponse> pages = buildPages(totalItems, pageSize);
        AtomicInteger callCount = new AtomicInteger(0);

        when(client.scan(any(ScanRequest.class)))
                .thenAnswer(
                        invocation -> {
                            ScanRequest req = invocation.getArgument(0);
                            assertNotNull(req.exclusiveStartKey());
                            return pages.get(callCount.getAndIncrement() + 1);
                        });
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();
        Map<String, AttributeValue> startKey =
                Map.of("Email", AttributeValue.builder().s("lastKey-5").build());

        var result = handler.scanSegment(0, 1, 3, 7500, startKey);

        assertEquals(5, result.itemsScanned());
        assertNull(result.lastEvaluatedKey());
    }

    @Test
    void shouldOnlyScanActiveSegmentsFromContinuationState() {
        when(configurationService.getInactiveAccountExportTotalSegments()).thenReturn(3);
        mockScanWithPagination(5, 5);
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();
        Map<Integer, Map<String, String>> segmentKeys = new HashMap<>();
        segmentKeys.put(1, Map.of("Email", "user5@example.com"));

        var request = new InactiveAccountDataExportRequest(segmentKeys, 100L, 0L);
        var response = handler.handleRequest(request, context);

        assertEquals(105, response.processedCount());
        assertEquals(0, response.writtenCount());
        verify(client, times(1)).scan(any(ScanRequest.class));
    }

    @Test
    void shouldAccumulateProcessedCountFromPreviousInvocations() {
        int itemCount = 5;
        mockScanWithPagination(itemCount, itemCount);
        mockBatchGetItemWithFullMatch();

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, 500L, 0L);

        var response = handler.handleRequest(request, context);

        assertEquals(505, response.processedCount());
        assertEquals(0, response.writtenCount());
    }

    @Test
    void shouldSerialiseContinuationStateAsJson() {
        Gson gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();

        var request =
                new InactiveAccountDataExportRequest(
                        Map.of(0, Map.of("Email", "user5@example.com")), 100L, 0L);

        String json = gson.toJson(request);
        var deserialised = gson.fromJson(json, InactiveAccountDataExportRequest.class);

        assertEquals(request.processedCount(), deserialised.processedCount());
        assertEquals(request.writtenCount(), deserialised.writtenCount());
        assertEquals(
                request.segmentKeys().get(0).get("Email"),
                deserialised.segmentKeys().get(0).get("Email"));
    }

    @Test
    void shouldDeserialiseEmptyPayloadAsFirstInvocation() {
        Gson gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();

        var deserialised = gson.fromJson("{}", InactiveAccountDataExportRequest.class);

        assertNull(deserialised.segmentKeys());
        assertNull(deserialised.processedCount());
        assertNull(deserialised.writtenCount());
    }

    private Map<String, AttributeValue> createItem(int index) {
        var profile =
                new UserProfile()
                        .withEmail("user" + index + "@example.com")
                        .withCreated("2024-01-15")
                        .withUpdated("2024-06-20")
                        .withPublicSubjectID("public-subject-" + index)
                        .withSubjectID("subject-" + index)
                        .withSalt(ByteBuffer.wrap(new byte[] {(byte) index, 42}))
                        .withTermsAndConditions(
                                new TermsAndConditions("1.5", "2024-01-15T09:30:00Z"));
        return USER_PROFILE_SCHEMA.itemToMap(profile, true);
    }

    private Map<String, AttributeValue> createCredentialItem(String email) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("Email", AttributeValue.builder().s(email).build());
        item.put("Created", AttributeValue.builder().s("2024-01-15").build());
        item.put("Updated", AttributeValue.builder().s("2024-06-20").build());
        item.put("MigratedPassword", AttributeValue.builder().s("migrated-hash").build());
        return item;
    }

    private void mockScanWithPagination(int totalItems, int pageSize) {
        List<ScanResponse> pages = buildPages(totalItems, pageSize);
        AtomicInteger callCount = new AtomicInteger(0);

        when(client.scan(any(ScanRequest.class)))
                .thenAnswer(invocation -> pages.get(callCount.getAndIncrement()));
    }

    private void mockBatchGetItemWithFullMatch() {
        when(client.batchGetItem(any(BatchGetItemRequest.class)))
                .thenAnswer(
                        invocation -> {
                            BatchGetItemRequest request = invocation.getArgument(0);
                            KeysAndAttributes keysAndAttrs =
                                    request.requestItems().get(USER_CREDENTIALS_TABLE);
                            if (keysAndAttrs == null || keysAndAttrs.keys().isEmpty()) {
                                return BatchGetItemResponse.builder()
                                        .responses(Map.of(USER_CREDENTIALS_TABLE, List.of()))
                                        .build();
                            }
                            List<Map<String, AttributeValue>> results = new ArrayList<>();
                            for (Map<String, AttributeValue> key : keysAndAttrs.keys()) {
                                String email = key.get("Email").s();
                                results.add(createCredentialItem(email));
                            }
                            return BatchGetItemResponse.builder()
                                    .responses(Map.of(USER_CREDENTIALS_TABLE, results))
                                    .build();
                        });
    }

    private List<ScanResponse> buildPages(int totalItems, int pageSize) {
        List<Map<String, AttributeValue>> allItems = new ArrayList<>();
        for (int i = 1; i <= totalItems; i++) {
            allItems.add(createItem(i));
        }

        List<ScanResponse> pages = new ArrayList<>();
        if (totalItems == 0) {
            pages.add(ScanResponse.builder().items(List.of()).count(0).scannedCount(0).build());
            return pages;
        }

        for (int start = 0; start < totalItems; start += pageSize) {
            int end = Math.min(start + pageSize, totalItems);
            List<Map<String, AttributeValue>> pageItems = allItems.subList(start, end);
            boolean hasMorePages = end < totalItems;

            ScanResponse.Builder responseBuilder =
                    ScanResponse.builder()
                            .items(pageItems)
                            .count(pageItems.size())
                            .scannedCount(pageItems.size());

            if (hasMorePages) {
                responseBuilder.lastEvaluatedKey(
                        Map.of(
                                UserProfile.ATTRIBUTE_EMAIL,
                                AttributeValue.builder().s("lastKey-" + end).build()));
            }

            pages.add(responseBuilder.build());
        }
        return pages;
    }
}
