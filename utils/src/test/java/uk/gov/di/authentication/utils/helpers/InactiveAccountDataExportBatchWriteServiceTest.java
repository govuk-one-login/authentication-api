package uk.gov.di.authentication.utils.helpers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemResponse;
import uk.gov.di.authentication.utils.entity.InactiveAccountTrackerItem;

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

    private final DynamoDbClient client = mock(DynamoDbClient.class);

    @BeforeEach
    void setUp() {
        when(client.batchWriteItem(any(BatchWriteItemRequest.class)))
                .thenReturn(BatchWriteItemResponse.builder().build());
    }

    private InactiveAccountDataExportBatchWriteService createService() {
        return new InactiveAccountDataExportBatchWriteService(client, TABLE_NAME);
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

    private InactiveAccountTrackerItem createTrackerItem(int index) {
        return new InactiveAccountTrackerItem()
                .withDateForDeletion("2029-01-15")
                .withCommonSubjectId("subject-" + index)
                .withPublicSubjectId("public-subject-" + index)
                .withEmailAddress("user" + index + "@example.com");
    }
}
