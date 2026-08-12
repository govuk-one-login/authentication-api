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

import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.backoff;

public class InactiveAccountDataExportBatchWriteService {

    private static final Logger LOG =
            LogManager.getLogger(InactiveAccountDataExportBatchWriteService.class);

    static final int BATCH_WRITE_ITEM_MAX_SIZE = 25;

    private static final TableSchema<InactiveAccountTrackerItem> TRACKER_ITEM_SCHEMA =
            TableSchema.fromBean(InactiveAccountTrackerItem.class);

    private final DynamoDbClient client;
    private final String tableName;
    private final int maxRetries;
    private final boolean dryRun;
    private final List<InactiveAccountTrackerItem> buffer = new ArrayList<>();
    private long totalWritten;
    private long totalFailed;
    private long totalBatchesFlushed;

    public InactiveAccountDataExportBatchWriteService(
            DynamoDbClient client, String tableName, int maxRetries) {
        this(client, tableName, maxRetries, false);
    }

    public InactiveAccountDataExportBatchWriteService(
            DynamoDbClient client, String tableName, int maxRetries, boolean dryRun) {
        this.client = client;
        this.tableName = tableName;
        this.maxRetries = maxRetries;
        this.dryRun = dryRun;
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

    public long getTotalFailed() {
        return totalFailed;
    }

    public long getTotalBatchesFlushed() {
        return totalBatchesFlushed;
    }

    private void flush() {
        List<WriteRequest> writeRequests = toWriteRequests(buffer);
        int itemCount = buffer.size();
        buffer.clear();

        if (dryRun) {
            totalWritten += itemCount;
            totalBatchesFlushed++;
            LOG.info(
                    "Dry-run mode enabled: {} items would have been written to tracker table (batch {})",
                    itemCount,
                    totalBatchesFlushed);
            return;
        }

        int retryCount = 0;

        while (!writeRequests.isEmpty()) {
            BatchWriteItemResponse response =
                    client.batchWriteItem(
                            BatchWriteItemRequest.builder()
                                    .requestItems(Map.of(tableName, writeRequests))
                                    .build());

            List<WriteRequest> unprocessedItems = extractUnprocessedItems(response);

            int writtenThisCall = writeRequests.size() - unprocessedItems.size();
            totalWritten += writtenThisCall;

            writeRequests = unprocessedItems;

            if (!writeRequests.isEmpty()) {
                retryCount++;
                if (retryCount > maxRetries) {
                    LOG.error(
                            "Failed to write {} items after {} retries",
                            writeRequests.size(),
                            maxRetries);
                    totalFailed += writeRequests.size();
                    break;
                }
                LOG.warn(
                        "{} unprocessed write items (attempt {}/{})",
                        writeRequests.size(),
                        retryCount,
                        maxRetries);
                backoff(retryCount);
            }
        }

        totalBatchesFlushed++;
    }

    private List<WriteRequest> extractUnprocessedItems(BatchWriteItemResponse response) {
        if (response.hasUnprocessedItems() && response.unprocessedItems().containsKey(tableName)) {
            return response.unprocessedItems().get(tableName);
        }
        return List.of();
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
