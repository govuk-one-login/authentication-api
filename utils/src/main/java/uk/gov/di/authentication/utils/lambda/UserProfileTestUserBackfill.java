package uk.gov.di.authentication.utils.lambda;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import software.amazon.awssdk.services.dynamodb.model.RequestLimitExceededException;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.awssdk.services.dynamodb.paginators.ScanIterable;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class UserProfileTestUserBackfill {
    private static final String PARTITION_KEY_NAME = "Email";
    private static final String ATTRIBUTE_TO_SET = "testUser";
    private static final AttributeValue DEFAULT_VALUE = AttributeValue.builder().n("0").build();
    private static final Region REGION = Region.EU_WEST_2;
    private static final int TOTAL_SEGMENTS = 16;
    private static final int SHUTDOWN_WAIT_MINUTES = 14;
    private static final Logger LOG = LogManager.getLogger(UserProfileTestUserBackfill.class);

    private DynamoDbClient dynamoDbClient;
    private String tableName;

    private static final AtomicLong itemsScanned = new AtomicLong(0);
    private static final AtomicLong itemsUpdated = new AtomicLong(0);
    private static final AtomicLong itemsSkipped = new AtomicLong(0);
    private static final AtomicLong updateErrors = new AtomicLong(0);

    public void handleRequest() {
        var environment = System.getenv("ENVIRONMENT");
        tableName = environment + "-user-profile";
        var dynamoClientBuilder =
                DynamoDbClient.builder()
                        .region(REGION)
                        .credentialsProvider(DefaultCredentialsProvider.create());
        var endpointOverride = System.getenv("DYNAMO_ENDPOINT");
        if (endpointOverride != null) {
            dynamoClientBuilder.endpointOverride(URI.create(endpointOverride));
        }
        dynamoDbClient = dynamoClientBuilder.build();
        itemsScanned.set(0);
        itemsUpdated.set(0);
        itemsSkipped.set(0);
        updateErrors.set(0);

        LOG.info("Starting DynamoDB backfill process...");
        LOG.info("Table: {}", tableName);
        LOG.info("Partition Key: {}", PARTITION_KEY_NAME);
        LOG.info("Attribute: {}", ATTRIBUTE_TO_SET);
        LOG.info("Default Value: {}", DEFAULT_VALUE.n());
        LOG.info("Parallel Segments: {}", TOTAL_SEGMENTS);

        ExecutorService executorService = Executors.newFixedThreadPool(TOTAL_SEGMENTS);
        long startTime = System.currentTimeMillis();

        for (int i = 0; i < TOTAL_SEGMENTS; i++) {
            var backfillTask = getBackfillTask(i);
            executorService.submit(backfillTask);
        }

        LOG.info("All tasks submitted. Waiting for completion...");
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(SHUTDOWN_WAIT_MINUTES, TimeUnit.MINUTES)) {
                LOG.error("Executor did not terminate in {} minutes.", SHUTDOWN_WAIT_MINUTES);
                executorService.shutdownNow();
            }
        } catch (InterruptedException ie) {
            LOG.error("Interrupted. Shutting down.");
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }

        long endTime = System.currentTimeMillis();
        long durationSeconds = (endTime - startTime) / 1000;

        // 4. Print Summary
        LOG.info("\n--- Backfill Summary ---");
        LOG.info("Total execution time: {} seconds", durationSeconds);
        LOG.info("Total items scanned (approx): {}", itemsScanned.get());
        LOG.info("Items updated (attribute added): {}", itemsUpdated.get());
        LOG.info("Items skipped (attribute already existed): {}", itemsSkipped.get());
        LOG.info("Update errors encountered: {}", updateErrors.get());
        LOG.info("Backfill process finished.");
    }

    private Runnable getBackfillTask(int i) {
        final int segment = i;
        return () -> {
            LOG.info("Starting task for segment {}/{}", segment, TOTAL_SEGMENTS);
            try {
                processSegment(segment);
            } catch (Exception e) {
                LOG.atError()
                        .withThrowable(e)
                        .log("Error processing segment {}: {}", segment, e.getMessage());
            }
            LOG.info("Finished task for segment {}/{}", segment, TOTAL_SEGMENTS);
        };
    }

    private void processSegment(int segment) {
        lazyGetRecordsToUpdate(segment).stream().forEach(this::updatePageOfRecords);
    }

    private ScanIterable lazyGetRecordsToUpdate(int segment) {
        Map<String, String> expressionAttributeNames =
                Map.of("#pk", PARTITION_KEY_NAME, "#attrToSet", ATTRIBUTE_TO_SET);
        ScanRequest scanRequest =
                ScanRequest.builder()
                        .tableName(tableName)
                        .segment(segment)
                        .totalSegments(TOTAL_SEGMENTS)
                        .projectionExpression("#pk")
                        .filterExpression("attribute_not_exists(#attrToSet)")
                        .expressionAttributeNames(expressionAttributeNames)
                        .consistentRead(false)
                        .build();

        return dynamoDbClient.scanPaginator(scanRequest);
    }

    private void updatePageOfRecords(ScanResponse page) {
        page.items().forEach(this::updateRecord);
    }

    private void updateRecord(Map<String, AttributeValue> itemKeys) {
        itemsScanned.incrementAndGet();

        AttributeValue partitionKeyValue = itemKeys.get(PARTITION_KEY_NAME);
        if (partitionKeyValue == null) {
            updateErrors.incrementAndGet();
            return;
        }

        Map<String, AttributeValue> keyToUpdate = Map.of(PARTITION_KEY_NAME, partitionKeyValue);

        Map<String, String> expressionAttributeNames = Map.of("#attrToSet", ATTRIBUTE_TO_SET);
        try {
            UpdateItemRequest updateRequest =
                    UpdateItemRequest.builder()
                            .tableName(tableName)
                            .key(keyToUpdate)
                            .updateExpression("SET #attrToSet = :val")
                            .conditionExpression("attribute_not_exists(#attrToSet)")
                            .expressionAttributeNames(expressionAttributeNames)
                            .expressionAttributeValues(Map.of(":val", DEFAULT_VALUE))
                            .build();

            dynamoDbClient.updateItem(updateRequest);
            itemsUpdated.incrementAndGet();

        } catch (ConditionalCheckFailedException e) {
            itemsSkipped.incrementAndGet();
        } catch (RequestLimitExceededException e) {
            updateErrors.incrementAndGet();
            LOG.warn(
                    "WARN: Update throttled. SDK might retry. Consider slowing down or increasing WCU.",
                    e);
            try {
                Thread.sleep(500);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        } catch (DynamoDbException e) {
            updateErrors.incrementAndGet();
            LOG.error("ERROR: Failed to update item.", e);
            try {
                Thread.sleep(100);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
