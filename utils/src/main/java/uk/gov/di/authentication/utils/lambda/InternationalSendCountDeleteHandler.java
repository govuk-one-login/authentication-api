package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.DeleteRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import software.amazon.awssdk.services.dynamodb.model.WriteRequest;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class InternationalSendCountDeleteHandler implements RequestHandler<Void, Void> {

    private static final Logger LOG =
            LogManager.getLogger(InternationalSendCountDeleteHandler.class);
    private static final int BATCH_SIZE = 25;
    private final DynamoDbClient client;
    private final String tableName;

    public InternationalSendCountDeleteHandler(
            ConfigurationService configurationService, DynamoDbClient client) {
        this.client = client;
        this.tableName =
                TableNameHelper.getFullTableName(
                        "international-sms-send-count", configurationService);
    }

    public InternationalSendCountDeleteHandler() {
        this(
                ConfigurationService.getInstance(),
                createDynamoClient(ConfigurationService.getInstance()));
    }

    @Override
    public Void handleRequest(Void input, Context context) {
        deleteAllItems();

        logRemainingItemCount();

        return null;
    }

    private void deleteAllItems() {
        Map<String, AttributeValue> lastKey = null;
        do {
            var scanBuilder =
                    ScanRequest.builder().tableName(tableName).projectionExpression("PhoneNumber");
            if (lastKey != null) {
                scanBuilder.exclusiveStartKey(lastKey);
            }
            ScanResponse response = client.scan(scanBuilder.build());
            deleteItems(response.items());
            lastKey = response.lastEvaluatedKey();
        } while (lastKey != null && !lastKey.isEmpty());
    }

    private void deleteItems(List<Map<String, AttributeValue>> items) {
        List<WriteRequest> batch = new ArrayList<>();
        for (var item : items) {
            batch.add(
                    WriteRequest.builder()
                            .deleteRequest(
                                    DeleteRequest.builder()
                                            .key(Map.of("PhoneNumber", item.get("PhoneNumber")))
                                            .build())
                            .build());
            if (batch.size() == BATCH_SIZE) {
                flushBatch(batch);
                batch = new ArrayList<>();
            }
        }
        if (!batch.isEmpty()) {
            flushBatch(batch);
        }
    }

    private void flushBatch(List<WriteRequest> batch) {
        client.batchWriteItem(
                BatchWriteItemRequest.builder().requestItems(Map.of(tableName, batch)).build());
    }

    private void logRemainingItemCount() {
        int remainingCount =
                client.scan(ScanRequest.builder().tableName(tableName).select("COUNT").build())
                        .count();
        LOG.info("International send count table item count after deletion: {}", remainingCount);
    }
}
