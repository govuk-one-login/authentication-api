package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.utils.entity.InactiveAccountDataExportRequest;
import uk.gov.di.authentication.utils.entity.InactiveAccountDataExportResponse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.TimeUnit;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.backoff;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.buildCredentialKeys;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.countMissingCredentials;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.extractUnprocessedKeys;

public class InactiveAccountDataExportHandler
        implements RequestHandler<
                InactiveAccountDataExportRequest, InactiveAccountDataExportResponse> {

    private static final Logger LOG = LogManager.getLogger(InactiveAccountDataExportHandler.class);
    private static final String USER_PROFILE_TABLE = "user-profile";
    private static final String USER_CREDENTIALS_TABLE = "user-credentials";
    private static final int BATCH_GET_ITEM_MAX_SIZE = 100;

    private static final String USER_PROFILE_PROJECTION_EXPRESSION =
            "Email,Created,Updated,termsAndConditions.#ts,PublicSubjectID,SubjectID,salt";
    private static final Map<String, String> USER_PROFILE_EXPRESSION_ATTRIBUTE_NAMES =
            Map.of("#ts", "timestamp");
    private static final String USER_CREDENTIALS_PROJECTION_EXPRESSION =
            "Email,Created,Updated,MigratedPassword";

    private final DynamoDbClient client;
    private final ConfigurationService configurationService;
    private final String userProfileTableName;
    private final String userCredentialsTableName;

    public InactiveAccountDataExportHandler(
            ConfigurationService configurationService, DynamoDbClient client) {
        this.client = client;
        this.configurationService = configurationService;
        this.userProfileTableName =
                TableNameHelper.getFullTableName(USER_PROFILE_TABLE, configurationService);
        this.userCredentialsTableName =
                TableNameHelper.getFullTableName(USER_CREDENTIALS_TABLE, configurationService);
    }

    public InactiveAccountDataExportHandler() {
        this(
                ConfigurationService.getInstance(),
                createDynamoClient(ConfigurationService.getInstance()));
    }

    @Override
    public InactiveAccountDataExportResponse handleRequest(
            InactiveAccountDataExportRequest request, Context context) {
        int parallelism = configurationService.getInactiveAccountExportParallelism();
        int totalSegments = configurationService.getInactiveAccountExportTotalSegments();
        int maxRetries = configurationService.getInactiveAccountExportMaxRetries();

        LOG.info(
                "Inactive account data export request: parallelism={}, totalSegments={}, maxRetries={}",
                parallelism,
                totalSegments,
                maxRetries);

        List<ForkJoinTask<SegmentResult>> tasks = new ArrayList<>();
        ForkJoinPool forkJoinPool = new ForkJoinPool(parallelism);

        try {
            for (int segment = 0; segment < totalSegments; segment++) {
                final int currentSegment = segment;
                tasks.add(
                        forkJoinPool.submit(
                                () -> scanSegment(currentSegment, totalSegments, maxRetries)));
            }

            gracefulPoolShutdown(forkJoinPool);

            long totalItemsScanned = 0;
            long totalMissingCredentials = 0;
            for (ForkJoinTask<SegmentResult> task : tasks) {
                SegmentResult result = task.join();
                totalItemsScanned += result.itemsScanned();
                totalMissingCredentials += result.missingCredentialsCount();
            }

            LOG.info(
                    "Scan completed: {} total items scanned, {} missing credentials",
                    totalItemsScanned,
                    totalMissingCredentials);

            return new InactiveAccountDataExportResponse(totalItemsScanned);
        } finally {
            forcePoolShutdown(forkJoinPool);
        }
    }

    private SegmentResult scanSegment(int segment, int totalSegments, int maxRetries) {
        Map<String, AttributeValue> lastKey = null;
        long itemsScanned = 0;
        long missingCredentialsCount = 0;
        List<Map<String, AttributeValue>> currentBatch = new ArrayList<>();

        do {
            ScanRequest.Builder requestBuilder =
                    ScanRequest.builder()
                            .tableName(userProfileTableName)
                            .segment(segment)
                            .totalSegments(totalSegments)
                            .projectionExpression(USER_PROFILE_PROJECTION_EXPRESSION)
                            .expressionAttributeNames(USER_PROFILE_EXPRESSION_ATTRIBUTE_NAMES);

            if (lastKey != null && !lastKey.isEmpty()) {
                requestBuilder.exclusiveStartKey(lastKey);
            }

            ScanResponse response;
            try {
                response = client.scan(requestBuilder.build());
            } catch (Exception e) {
                LOG.error(
                        "Scan failed for segment {}: {} - {}",
                        segment,
                        e.getClass().getSimpleName(),
                        e.getMessage());
                throw e;
            }

            for (Map<String, AttributeValue> item : response.items()) {
                itemsScanned++;
                currentBatch.add(item);

                if (currentBatch.size() >= BATCH_GET_ITEM_MAX_SIZE) {
                    missingCredentialsCount += batchGetUserCredentials(currentBatch, maxRetries);
                    currentBatch.clear();
                }
            }

            lastKey = response.lastEvaluatedKey();
        } while (lastKey != null && !lastKey.isEmpty());

        if (!currentBatch.isEmpty()) {
            missingCredentialsCount += batchGetUserCredentials(currentBatch, maxRetries);
            currentBatch.clear();
        }

        LOG.info(
                "Segment {} completed: {} items scanned, {} missing credentials",
                segment,
                itemsScanned,
                missingCredentialsCount);

        return new SegmentResult(itemsScanned, missingCredentialsCount);
    }

    private long batchGetUserCredentials(
            List<Map<String, AttributeValue>> userProfileItems, int maxRetries) {
        if (userProfileItems.isEmpty()) {
            return 0;
        }

        List<Map<String, AttributeValue>> keys = buildCredentialKeys(userProfileItems);
        if (keys.isEmpty()) {
            return userProfileItems.size();
        }

        List<Map<String, AttributeValue>> results = fetchWithRetry(keys, maxRetries);

        return countMissingCredentials(keys.size(), results.size());
    }

    private List<Map<String, AttributeValue>> fetchWithRetry(
            List<Map<String, AttributeValue>> keys, int maxRetries) {
        List<Map<String, AttributeValue>> allResults = new ArrayList<>();

        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        requestItems.put(
                userCredentialsTableName,
                KeysAndAttributes.builder()
                        .keys(keys)
                        .projectionExpression(USER_CREDENTIALS_PROJECTION_EXPRESSION)
                        .build());

        int retryCount = 0;

        while (!requestItems.isEmpty()) {
            BatchGetItemResponse response =
                    client.batchGetItem(
                            BatchGetItemRequest.builder().requestItems(requestItems).build());

            List<Map<String, AttributeValue>> results =
                    response.responses().get(userCredentialsTableName);
            if (results != null) {
                allResults.addAll(results);
            }

            requestItems = extractUnprocessedKeys(response, userCredentialsTableName);

            if (!requestItems.isEmpty()) {
                retryCount++;
                int unprocessedCount = requestItems.get(userCredentialsTableName).keys().size();
                if (retryCount > maxRetries) {
                    LOG.error(
                            "Failed to process {} keys after {} retries",
                            unprocessedCount,
                            maxRetries);
                    break;
                }
                LOG.warn(
                        "{} unprocessed keys (attempt {}/{})",
                        unprocessedCount,
                        retryCount,
                        maxRetries);
                backoff(retryCount);
            }
        }

        return allResults;
    }

    private record SegmentResult(long itemsScanned, long missingCredentialsCount) {}

    private static void gracefulPoolShutdown(ForkJoinPool forkJoinPool) {
        forkJoinPool.shutdown();
        try {
            if (!forkJoinPool.awaitTermination(15, TimeUnit.MINUTES)) {
                LOG.warn("ForkJoinPool did not terminate within 15 minutes");
            }
        } catch (InterruptedException e) {
            LOG.error("ForkJoinPool termination interrupted", e);
            Thread.currentThread().interrupt();
        }
    }

    private static void forcePoolShutdown(ForkJoinPool forkJoinPool) {
        if (!forkJoinPool.isShutdown()) {
            forkJoinPool.shutdownNow();
        }
    }
}
