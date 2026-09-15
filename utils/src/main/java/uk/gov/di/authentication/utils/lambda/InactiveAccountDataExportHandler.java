package uk.gov.di.authentication.utils.lambda;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.utils.entity.InactiveAccountDataExportRequest;
import uk.gov.di.authentication.utils.entity.InactiveAccountDataExportResponse;
import uk.gov.di.authentication.utils.entity.InactiveAccountTrackerItem;
import uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportBatchWriteService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.backoff;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.buildCredentialKeys;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.buildTrackerItem;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.countMissingCredentials;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.ensureSaltPresent;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.extractUnprocessedKeys;

public class InactiveAccountDataExportHandler
        extends ChainedParallelScanHandler<
                InactiveAccountDataExportRequest, InactiveAccountDataExportResponse> {

    private static final Logger LOG = LogManager.getLogger(InactiveAccountDataExportHandler.class);
    private static final String USER_PROFILE_TABLE = "user-profile";
    private static final String USER_CREDENTIALS_TABLE = "user-credentials";
    private static final int BATCH_GET_ITEM_MAX_SIZE = 100;

    private static final String USER_PROFILE_PROJECTION_EXPRESSION =
            "Email,Created,Updated,termsAndConditions.#ts,PublicSubjectID,SubjectID,salt,PhoneNumberVerified,mfaMethodsMigrated,LastSignedIn";
    private static final Map<String, String> USER_PROFILE_EXPRESSION_ATTRIBUTE_NAMES =
            Map.of("#ts", "timestamp");
    private static final String USER_CREDENTIALS_PROJECTION_EXPRESSION =
            "Email,Created,Updated,MigratedPassword,MfaMethods";

    private final DynamoDbClient client;
    private final String userProfileTableName;
    private final String userCredentialsTableName;
    private final String exportTableName;
    private final int parallelism;
    private final int totalSegments;
    private final int maxRetries;
    private final int batchWriteMaxRetries;
    private final int maxItemsPerSegment;
    private final long pauseBetweenInvocationsMs;
    private final String lambdaName;
    private final int maxInvocations;
    private final String internalSectorUri;
    private final boolean trackerWriteEnabled;

    private final AtomicLong invocationWrittenCount = new AtomicLong(0);
    private final AtomicLong invocationMissingCredentialsCount = new AtomicLong(0);
    private final AtomicLong runningWrittenCount = new AtomicLong(0);

    public InactiveAccountDataExportHandler(
            ConfigurationService configurationService,
            DynamoDbClient client,
            LambdaInvokerService lambdaInvokerService) {
        super(lambdaInvokerService);
        this.client = client;
        this.userProfileTableName =
                TableNameHelper.getFullTableName(USER_PROFILE_TABLE, configurationService);
        this.userCredentialsTableName =
                TableNameHelper.getFullTableName(USER_CREDENTIALS_TABLE, configurationService);
        this.exportTableName = configurationService.getInactiveAccountExportTableName();
        this.parallelism = configurationService.getInactiveAccountExportParallelism();
        this.totalSegments = configurationService.getInactiveAccountExportTotalSegments();
        this.maxRetries = configurationService.getInactiveAccountExportMaxRetries();
        this.batchWriteMaxRetries =
                configurationService.getInactiveAccountExportBatchWriteMaxRetries();
        this.maxItemsPerSegment = configurationService.getInactiveAccountExportMaxItemsPerSegment();
        this.pauseBetweenInvocationsMs =
                configurationService.getInactiveAccountExportPauseBetweenInvocationsMs();
        this.lambdaName = configurationService.getInactiveAccountExportLambdaName();
        this.maxInvocations = configurationService.getInactiveAccountExportMaxInvocations();
        this.internalSectorUri = configurationService.getInternalSectorUri();
        this.trackerWriteEnabled =
                configurationService.isInactiveAccountExportTrackerWriteEnabled();
    }

    public InactiveAccountDataExportHandler() {
        this(
                ConfigurationService.getInstance(),
                createDynamoClient(ConfigurationService.getInstance()),
                new LambdaInvokerService(ConfigurationService.getInstance()));
    }

    @Override
    protected int getMaxInvocations() {
        return maxInvocations;
    }

    @Override
    protected int getParallelism() {
        return parallelism;
    }

    @Override
    protected int getTotalSegments() {
        return totalSegments;
    }

    @Override
    protected int getMaxItemsPerSegment() {
        return maxItemsPerSegment;
    }

    @Override
    protected long getPauseBetweenInvocationsMs() {
        return pauseBetweenInvocationsMs;
    }

    @Override
    protected String getLambdaName() {
        return lambdaName;
    }

    @Override
    protected Map<Integer, Map<String, String>> getSegmentKeysFromRequest(
            InactiveAccountDataExportRequest request) {
        return request != null ? request.segmentKeys() : null;
    }

    @Override
    protected long getProcessedCountFromRequest(InactiveAccountDataExportRequest request) {
        return request != null && request.processedCount() != null ? request.processedCount() : 0L;
    }

    @Override
    protected long getInvocationCountFromRequest(InactiveAccountDataExportRequest request) {
        return request != null && request.invocationCount() != null
                ? request.invocationCount()
                : 0L;
    }

    @Override
    protected void beforeScan(InactiveAccountDataExportRequest request) {
        LOG.info("Tracker write enabled: {}", trackerWriteEnabled);
        runningWrittenCount.set(
                request != null && request.writtenCount() != null ? request.writtenCount() : 0L);
        invocationWrittenCount.set(0);
        invocationMissingCredentialsCount.set(0);
    }

    @Override
    protected void onMaxInvocationsExceeded(
            long invocationCount, long maxInvocations, long processedCount) {
        LOG.warn(
                "INACTIVE_ACCOUNT_DATA_EXPORT_MAX_INVOCATIONS_EXCEEDED: invocationCount={} "
                        + "has reached or exceeded maxInvocations={}, halting self-invocation "
                        + "chain. processedCount={}, writtenCount={}",
                invocationCount,
                maxInvocations,
                processedCount,
                runningWrittenCount.get());
    }

    @Override
    protected InactiveAccountDataExportResponse buildEarlyExitResponse(
            InactiveAccountDataExportRequest request) {
        long processedCount = getProcessedCountFromRequest(request);
        long writtenCount =
                request != null && request.writtenCount() != null ? request.writtenCount() : 0L;
        return new InactiveAccountDataExportResponse(processedCount, writtenCount);
    }

    @Override
    protected void onInvocationComplete(
            long processedThisInvocation, long totalProcessed, int segmentsRemaining) {
        long written = invocationWrittenCount.get();
        long missing = invocationMissingCredentialsCount.get();
        runningWrittenCount.addAndGet(written);

        LOG.info(
                "Invocation complete: {} items scanned this invocation, {} missing credentials, "
                        + "{} total processed, {} written this invocation, "
                        + "{} total written, {} segments remaining",
                processedThisInvocation,
                missing,
                totalProcessed,
                written,
                runningWrittenCount.get(),
                segmentsRemaining);
    }

    @Override
    protected InactiveAccountDataExportRequest buildContinuationRequest(
            Map<Integer, Map<String, String>> remainingSegmentKeys,
            long processedCount,
            long invocationCount) {
        return new InactiveAccountDataExportRequest(
                remainingSegmentKeys, processedCount, runningWrittenCount.get(), invocationCount);
    }

    @Override
    protected InactiveAccountDataExportResponse buildResponse(long processedCount) {
        return new InactiveAccountDataExportResponse(processedCount, runningWrittenCount.get());
    }

    @Override
    protected SegmentResult processSegment(
            int segment,
            int totalSegments,
            int maxItemsPerSegment,
            Map<String, AttributeValue> exclusiveStartKey) {
        ScanSegmentResult result =
                scanSegment(
                        segment, totalSegments, maxRetries, maxItemsPerSegment, exclusiveStartKey);
        invocationWrittenCount.addAndGet(result.writtenCount());
        invocationMissingCredentialsCount.addAndGet(result.missingCredentialsCount());
        return new SegmentResult(result.itemsScanned(), result.lastEvaluatedKey());
    }

    ScanSegmentResult scanSegment(
            int segment,
            int totalSegments,
            int maxRetries,
            int maxItemsPerSegment,
            Map<String, AttributeValue> exclusiveStartKey) {
        Map<String, AttributeValue> lastKey = exclusiveStartKey;
        long itemsScanned = 0;
        long missingCredentialsCount = 0;
        List<Map<String, AttributeValue>> currentBatch = new ArrayList<>();
        InactiveAccountDataExportBatchWriteService batchWriteService =
                new InactiveAccountDataExportBatchWriteService(
                        client, exportTableName, batchWriteMaxRetries, !trackerWriteEnabled);

        boolean hasMorePages = true;
        while (hasMorePages && itemsScanned < maxItemsPerSegment) {
            ScanRequest.Builder requestBuilder =
                    ScanRequest.builder()
                            .tableName(userProfileTableName)
                            .segment(segment)
                            .totalSegments(totalSegments)
                            .limit(maxItemsPerSegment)
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

            for (var item : response.items()) {
                itemsScanned++;
                currentBatch.add(item);

                if (currentBatch.size() >= BATCH_GET_ITEM_MAX_SIZE) {
                    missingCredentialsCount +=
                            batchGetUserCredentials(currentBatch, maxRetries, batchWriteService);
                    currentBatch.clear();
                }
            }

            lastKey = response.lastEvaluatedKey();
            hasMorePages = lastKey != null && !lastKey.isEmpty();
        }

        if (!currentBatch.isEmpty()) {
            missingCredentialsCount +=
                    batchGetUserCredentials(currentBatch, maxRetries, batchWriteService);
            currentBatch.clear();
        }

        batchWriteService.flushRemaining();

        Map<String, AttributeValue> finalKey =
                (lastKey != null && !lastKey.isEmpty()) ? lastKey : null;

        LOG.info(
                "Segment {} completed: {} items scanned, {} missing credentials, "
                        + "{} items written, {} batches flushed, segmentExhausted={}",
                segment,
                itemsScanned,
                missingCredentialsCount,
                batchWriteService.getTotalWritten(),
                batchWriteService.getTotalBatchesFlushed(),
                finalKey == null);

        return new ScanSegmentResult(
                itemsScanned,
                missingCredentialsCount,
                batchWriteService.getTotalWritten(),
                finalKey);
    }

    private long batchGetUserCredentials(
            List<Map<String, AttributeValue>> userProfileItems,
            int maxRetries,
            InactiveAccountDataExportBatchWriteService batchWriteService) {
        if (userProfileItems.isEmpty()) {
            return 0;
        }

        List<Map<String, AttributeValue>> keys = buildCredentialKeys(userProfileItems);
        if (keys.isEmpty()) {
            return userProfileItems.size();
        }

        List<Map<String, AttributeValue>> credentialResults = fetchWithRetry(keys, maxRetries);

        buildAndBufferTrackerItems(userProfileItems, credentialResults, batchWriteService);

        return countMissingCredentials(keys.size(), credentialResults.size());
    }

    private void buildAndBufferTrackerItems(
            List<Map<String, AttributeValue>> userProfileItems,
            List<Map<String, AttributeValue>> credentialResults,
            InactiveAccountDataExportBatchWriteService batchWriteService) {
        Map<String, Map<String, AttributeValue>> credentialsByEmail = new HashMap<>();
        for (Map<String, AttributeValue> credItem : credentialResults) {
            AttributeValue email = credItem.get(UserCredentials.ATTRIBUTE_EMAIL);
            if (email != null) {
                credentialsByEmail.put(email.s(), credItem);
            }
        }

        for (Map<String, AttributeValue> profileItem : userProfileItems) {
            AttributeValue email = profileItem.get(UserProfile.ATTRIBUTE_EMAIL);
            if (email == null) {
                continue;
            }
            Map<String, AttributeValue> mutableProfileItem = new HashMap<>(profileItem);
            ensureSaltPresent(mutableProfileItem, client, userProfileTableName);
            InactiveAccountTrackerItem trackerItem =
                    buildTrackerItem(
                            mutableProfileItem,
                            credentialsByEmail.get(email.s()),
                            internalSectorUri);
            if (trackerItem != null) {
                batchWriteService.add(trackerItem);
            }
        }
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

    record ScanSegmentResult(
            long itemsScanned,
            long missingCredentialsCount,
            long writtenCount,
            Map<String, AttributeValue> lastEvaluatedKey) {}
}
