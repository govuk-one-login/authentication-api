package uk.gov.di.authentication.utils.helpers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutRequest;
import software.amazon.awssdk.services.dynamodb.model.WriteRequest;
import uk.gov.di.authentication.utils.entity.InactiveAccountTrackerItem;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportBatchWriteService.BATCH_WRITE_ITEM_MAX_SIZE;

class InactiveAccountDataExportBatchWriteServiceTest {

    private static final String TABLE_NAME = "test-tracker-table";
    private static final int MAX_RETRIES = 3;

    private final DynamoDbClient client = mock(DynamoDbClient.class);

    @BeforeEach
    void setUp() {
        when(client.batchWriteItem(any(BatchWriteItemRequest.class)))
                .thenReturn(BatchWriteItemResponse.builder().build());
    }

    private InactiveAccountDataExportBatchWriteService createService() {
        return new InactiveAccountDataExportBatchWriteService(client, TABLE_NAME, MAX_RETRIES);
    }

    @Test
    void shouldFlushAutomaticallyAtBatchSize() {
        var service = createService();

        for (int i = 0; i < BATCH_WRITE_ITEM_MAX_SIZE; i++) {
            service.add(createTrackerItem(i));
        }

        verify(client, times(1)).batchWriteItem(any(BatchWriteItemRequest.class));
        assertEquals(BATCH_WRITE_ITEM_MAX_SIZE, service.getTotalWritten());
        assertEquals(1, service.getTotalBatchesFlushed());
    }

    @Test
    void shouldNotFlushWhenBelowBatchSize() {
        var service = createService();

        for (int i = 0; i < BATCH_WRITE_ITEM_MAX_SIZE - 1; i++) {
            service.add(createTrackerItem(i));
        }

        verify(client, never()).batchWriteItem(any(BatchWriteItemRequest.class));
    }

    @Test
    void shouldFlushRemainingAsPartialBatch() {
        var service = createService();
        int itemCount = 10;

        for (int i = 0; i < itemCount; i++) {
            service.add(createTrackerItem(i));
        }
        service.flushRemaining();

        verify(client, times(1)).batchWriteItem(any(BatchWriteItemRequest.class));
        assertEquals(itemCount, service.getTotalWritten());
        assertEquals(1, service.getTotalBatchesFlushed());
    }

    @Test
    void shouldNotFlushRemainingWhenBufferIsEmpty() {
        var service = createService();

        service.flushRemaining();

        verify(client, never()).batchWriteItem(any(BatchWriteItemRequest.class));
    }

    @Test
    void shouldFlushMultipleTimesAsItemsAccumulate() {
        var service = createService();
        int totalItems = BATCH_WRITE_ITEM_MAX_SIZE * 3;

        for (int i = 0; i < totalItems; i++) {
            service.add(createTrackerItem(i));
        }

        verify(client, times(3)).batchWriteItem(any(BatchWriteItemRequest.class));
        assertEquals(totalItems, service.getTotalWritten());
        assertEquals(3, service.getTotalBatchesFlushed());
    }

    @Test
    void shouldFlushFullBatchThenFlushRemainingPartialBatch() {
        var service = createService();
        int totalItems = BATCH_WRITE_ITEM_MAX_SIZE + 10;

        for (int i = 0; i < totalItems; i++) {
            service.add(createTrackerItem(i));
        }
        service.flushRemaining();

        verify(client, times(2)).batchWriteItem(any(BatchWriteItemRequest.class));
        assertEquals(totalItems, service.getTotalWritten());
        assertEquals(2, service.getTotalBatchesFlushed());
    }

    @Test
    void shouldRetryUnprocessedItemsSuccessfully() {
        int itemCount = 10;
        AtomicInteger callCount = new AtomicInteger(0);

        when(client.batchWriteItem(any(BatchWriteItemRequest.class)))
                .thenAnswer(
                        invocation -> {
                            int call = callCount.getAndIncrement();
                            if (call == 0) {
                                return responseWithUnprocessedItems(3);
                            }
                            return BatchWriteItemResponse.builder().build();
                        });

        var service = createService();
        for (int i = 0; i < itemCount; i++) {
            service.add(createTrackerItem(i));
        }
        service.flushRemaining();

        verify(client, times(2)).batchWriteItem(any(BatchWriteItemRequest.class));
        assertEquals(itemCount, service.getTotalWritten());
        assertEquals(0, service.getTotalFailed());
    }

    @Test
    void shouldCountFailedItemsAfterRetriesExhausted() {
        int itemCount = 10;
        int unprocessedCount = 3;

        when(client.batchWriteItem(any(BatchWriteItemRequest.class)))
                .thenReturn(responseWithUnprocessedItems(unprocessedCount));

        var service = createService();
        for (int i = 0; i < itemCount; i++) {
            service.add(createTrackerItem(i));
        }
        service.flushRemaining();

        // Initial call + 3 retries = 4 calls
        verify(client, times(MAX_RETRIES + 1)).batchWriteItem(any(BatchWriteItemRequest.class));
        assertEquals(itemCount - unprocessedCount, service.getTotalWritten());
        assertEquals(unprocessedCount, service.getTotalFailed());
    }

    @Test
    void shouldNotRetryWhenNoUnprocessedItems() {
        var service = createService();
        int itemCount = 10;

        for (int i = 0; i < itemCount; i++) {
            service.add(createTrackerItem(i));
        }
        service.flushRemaining();

        verify(client, times(1)).batchWriteItem(any(BatchWriteItemRequest.class));
        assertEquals(0, service.getTotalFailed());
    }

    private BatchWriteItemResponse responseWithUnprocessedItems(int count) {
        List<WriteRequest> unprocessed = new java.util.ArrayList<>();
        for (int i = 0; i < count; i++) {
            unprocessed.add(
                    WriteRequest.builder()
                            .putRequest(PutRequest.builder().item(Map.of()).build())
                            .build());
        }
        return BatchWriteItemResponse.builder()
                .unprocessedItems(Map.of(TABLE_NAME, unprocessed))
                .build();
    }

    private InactiveAccountTrackerItem createTrackerItem(int index) {
        return new InactiveAccountTrackerItem()
                .withDateForDeletion("2029-01-15")
                .withCommonSubjectId("subject-" + index)
                .withPublicSubjectId("public-subject-" + index)
                .withEmailAddress("user" + index + "@example.com");
    }
}
