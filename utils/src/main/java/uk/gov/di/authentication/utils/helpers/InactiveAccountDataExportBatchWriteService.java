package uk.gov.di.authentication.utils.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemResponse;
import software.amazon.awssdk.services.dynamodb.model.WriteRequest;
import uk.gov.di.authentication.utils.entity.InactiveAccountTrackerItem;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class InactiveAccountDataExportBatchWriteService {

    private static final Logger LOG =
            LogManager.getLogger(InactiveAccountDataExportBatchWriteService.class);

    static final int BATCH_WRITE_ITEM_MAX_SIZE = 25;

    private static final TableSchema<InactiveAccountTrackerItem> TRACKER_ITEM_SCHEMA =
            TableSchema.fromBean(InactiveAccountTrackerItem.class);

    private final DynamoDbClient client;
    private final String tableName;
    private final List<InactiveAccountTrackerItem> buffer = new ArrayList<>();
    private long totalWritten;
    private long totalBatchesFlushed;

    public InactiveAccountDataExportBatchWriteService(DynamoDbClient client, String tableName) {
        this.client = client;
        this.tableName = tableName;
    }

    public void add(InactiveAccountTrackerItem item) {
        buffer.add(item);
        if (buffer.size() == BATCH_WRITE_ITEM_MAX_SIZE) {
            flush();
        }
    }

    public void flushRemaining() {
        if (!buffer.isEmpty()) {
            flush();
        }
    }

    public long getTotalWritten() {
        return totalWritten;
    }

    public long getTotalBatchesFlushed() {
        return totalBatchesFlushed;
    }

    private void flush() {
        List<WriteRequest> writeRequests = toWriteRequests(buffer);

        BatchWriteItemResponse response =
                client.batchWriteItem(
                        BatchWriteItemRequest.builder()
                                .requestItems(Map.of(tableName, writeRequests))
                                .build());

        int unprocessedCount = 0;
        if (response.hasUnprocessedItems() && response.unprocessedItems().containsKey(tableName)) {
            unprocessedCount = response.unprocessedItems().get(tableName).size();
        }

        int written = buffer.size() - unprocessedCount;
        totalWritten += written;
        totalBatchesFlushed++;
        buffer.clear();

        if (unprocessedCount > 0) {
            LOG.warn("BatchWriteItem returned {} unprocessed items", unprocessedCount);
        }
    }

    private static List<WriteRequest> toWriteRequests(List<InactiveAccountTrackerItem> items) {
        List<WriteRequest> writeRequests = new ArrayList<>(items.size());

        for (InactiveAccountTrackerItem item : items) {
            writeRequests.add(
                    WriteRequest.builder()
                            .putRequest(pr -> pr.item(TRACKER_ITEM_SCHEMA.itemToMap(item, true)))
                            .build());
        }

        return writeRequests;
    }
}
