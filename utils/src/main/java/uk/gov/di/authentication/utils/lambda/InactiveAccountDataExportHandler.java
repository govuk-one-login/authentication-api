package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.utils.entity.InactiveAccountDataExportRequest;
import uk.gov.di.authentication.utils.entity.InactiveAccountDataExportResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.TimeUnit;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class InactiveAccountDataExportHandler
        implements RequestHandler<
                InactiveAccountDataExportRequest, InactiveAccountDataExportResponse> {

    private static final Logger LOG = LogManager.getLogger(InactiveAccountDataExportHandler.class);
    private static final String USER_PROFILE_TABLE = "user-profile";
    private static final String USER_CREDENTIALS_TABLE = "user-credentials";
    private static final int DEFAULT_MAX_RETRIES = 3;

    private static final String PROJECTION_EXPRESSION =
            "Email,Created,Updated,termsAndConditions.#ts,PublicSubjectID,SubjectID,salt";
    private static final Map<String, String> EXPRESSION_ATTRIBUTE_NAMES =
            Map.of("#ts", "timestamp");

    private final DynamoDbClient client;
    private final String userProfileTableName;
    private final String userCredentialsTableName;

    public InactiveAccountDataExportHandler(
            ConfigurationService configurationService, DynamoDbClient client) {
        this.client = client;
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
        if (request == null || request.parallelism() == null || request.totalSegments() == null) {
            throw new IllegalArgumentException(
                    "Request must contain 'parallelism' and 'totalSegments' fields.");
        }

        int parallelism = request.parallelism();
        int totalSegments = request.totalSegments();
        int maxRetries = request.maxRetries() != null ? request.maxRetries() : DEFAULT_MAX_RETRIES;

        LOG.info(
                "Inactive account data export request: parallelism={}, totalSegments={}, maxRetries={}",
                parallelism,
                totalSegments,
                maxRetries);

        List<ForkJoinTask<Long>> tasks = new ArrayList<>();
        ForkJoinPool forkJoinPool = new ForkJoinPool(parallelism);

        try {
            for (int segment = 0; segment < totalSegments; segment++) {
                final int currentSegment = segment;
                tasks.add(forkJoinPool.submit(() -> scanSegment(currentSegment, totalSegments)));
            }

            gracefulPoolShutdown(forkJoinPool);

            long totalItemsScanned = 0;
            for (ForkJoinTask<Long> task : tasks) {
                totalItemsScanned += task.join();
            }

            LOG.info("Scan completed: {} total items scanned", totalItemsScanned);

            return new InactiveAccountDataExportResponse(totalItemsScanned);
        } finally {
            forcePoolShutdown(forkJoinPool);
        }
    }

    private long scanSegment(int segment, int totalSegments) {
        Map<String, AttributeValue> lastKey = null;
        long itemsScanned = 0;

        do {
            ScanRequest.Builder requestBuilder =
                    ScanRequest.builder()
                            .tableName(userProfileTableName)
                            .segment(segment)
                            .totalSegments(totalSegments)
                            .projectionExpression(PROJECTION_EXPRESSION)
                            .expressionAttributeNames(EXPRESSION_ATTRIBUTE_NAMES);

            if (lastKey != null && !lastKey.isEmpty()) {
                requestBuilder.exclusiveStartKey(lastKey);
            }

            ScanResponse response = client.scan(requestBuilder.build());

            itemsScanned += response.items().size();

            lastKey = response.lastEvaluatedKey();
        } while (lastKey != null && !lastKey.isEmpty());

        LOG.info("Segment {} completed: {} items scanned", segment, itemsScanned);

        return itemsScanned;
    }

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
