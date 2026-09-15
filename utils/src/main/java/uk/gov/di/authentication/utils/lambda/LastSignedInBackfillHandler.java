package uk.gov.di.authentication.utils.lambda;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.utils.entity.LastSignedInBackfillRequest;
import uk.gov.di.authentication.utils.entity.LastSignedInBackfillResponse;
import uk.gov.di.authentication.utils.helpers.LastSignedInBackfillHelper;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class LastSignedInBackfillHandler
        extends ChainedParallelScanHandler<
                LastSignedInBackfillRequest, LastSignedInBackfillResponse> {

    private static final Logger LOG = LogManager.getLogger(LastSignedInBackfillHandler.class);

    private static final String USER_PROFILE_TABLE = "user-profile";

    private final DynamoDbClient client;
    private final String userProfileTableName;
    private final String trackerTableName;
    private final int parallelism;
    private final int totalSegments;
    private final int maxItemsPerSegment;
    private final long pauseBetweenInvocationsMs;
    private final String lambdaName;
    private final int maxInvocations;

    private final AtomicLong invocationUpdatedCount = new AtomicLong(0);
    private final AtomicLong invocationSkippedCount = new AtomicLong(0);
    private final AtomicLong runningUpdatedCount = new AtomicLong(0);
    private final AtomicLong runningSkippedCount = new AtomicLong(0);

    public LastSignedInBackfillHandler(
            ConfigurationService configurationService,
            DynamoDbClient client,
            LambdaInvokerService lambdaInvokerService) {
        super(lambdaInvokerService);
        this.client = client;
        this.userProfileTableName =
                TableNameHelper.getFullTableName(USER_PROFILE_TABLE, configurationService);
        this.trackerTableName = configurationService.getLastSignedInBackfillTrackerTableName();
        this.parallelism = configurationService.getLastSignedInBackfillParallelism();
        this.totalSegments = configurationService.getLastSignedInBackfillTotalSegments();
        this.maxItemsPerSegment = configurationService.getLastSignedInBackfillMaxItemsPerSegment();
        this.pauseBetweenInvocationsMs =
                configurationService.getLastSignedInBackfillPauseBetweenInvocationsMs();
        this.lambdaName = configurationService.getLastSignedInBackfillLambdaName();
        this.maxInvocations = configurationService.getLastSignedInBackfillMaxInvocations();
    }

    public LastSignedInBackfillHandler() {
        this(
                ConfigurationService.getInstance(),
                createDynamoClient(ConfigurationService.getInstance()),
                new LambdaInvokerService(ConfigurationService.getInstance()));
    }

    @Override
    protected Class<LastSignedInBackfillRequest> getRequestClass() {
        return LastSignedInBackfillRequest.class;
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
            LastSignedInBackfillRequest request) {
        return request != null ? request.segmentKeys() : null;
    }

    @Override
    protected long getProcessedCountFromRequest(LastSignedInBackfillRequest request) {
        return request != null && request.processedCount() != null ? request.processedCount() : 0L;
    }

    @Override
    protected long getInvocationCountFromRequest(LastSignedInBackfillRequest request) {
        return request != null && request.invocationCount() != null
                ? request.invocationCount()
                : 0L;
    }

    @Override
    protected void beforeScan(LastSignedInBackfillRequest request) {
        LOG.info(
                "lastSignedIn backfill: parallelism={}, totalSegments={}, maxItemsPerSegment={},"
                        + " processedCount={}",
                parallelism,
                totalSegments,
                maxItemsPerSegment,
                getProcessedCountFromRequest(request));
        runningUpdatedCount.set(
                request != null && request.updatedCount() != null ? request.updatedCount() : 0L);
        runningSkippedCount.set(
                request != null && request.skippedCount() != null ? request.skippedCount() : 0L);
        invocationUpdatedCount.set(0);
        invocationSkippedCount.set(0);
    }

    @Override
    protected void onMaxInvocationsExceeded(
            long invocationCount, long maxInvocations, long processedCount) {
        LOG.warn(
                "LAST_SIGNED_IN_BACKFILL_MAX_INVOCATIONS_EXCEEDED: invocationCount={} has"
                        + " reached or exceeded maxInvocations={}, halting self-invocation"
                        + " chain. processedCount={}, updatedCount={}, skippedCount={}",
                invocationCount,
                maxInvocations,
                processedCount,
                runningUpdatedCount.get(),
                runningSkippedCount.get());
    }

    @Override
    protected void onInvocationComplete(
            long processedThisInvocation, long totalProcessed, int segmentsRemaining) {
        long updated = invocationUpdatedCount.get();
        long skipped = invocationSkippedCount.get();
        runningUpdatedCount.addAndGet(updated);
        runningSkippedCount.addAndGet(skipped);

        LOG.info(
                "Invocation complete: processedThisInvocation={}, updatedThisInvocation={},"
                        + " skippedThisInvocation={}, totalProcessed={}, totalUpdated={},"
                        + " totalSkipped={}, segmentsRemaining={}",
                processedThisInvocation,
                updated,
                skipped,
                totalProcessed,
                runningUpdatedCount.get(),
                runningSkippedCount.get(),
                segmentsRemaining);
    }

    @Override
    protected LastSignedInBackfillRequest buildContinuationRequest(
            Map<Integer, Map<String, String>> remainingSegmentKeys,
            long processedCount,
            long invocationCount) {
        return new LastSignedInBackfillRequest(
                remainingSegmentKeys,
                processedCount,
                runningUpdatedCount.get(),
                runningSkippedCount.get(),
                invocationCount);
    }

    @Override
    protected LastSignedInBackfillResponse buildResponse(long processedCount) {
        return new LastSignedInBackfillResponse(
                processedCount, runningUpdatedCount.get(), runningSkippedCount.get());
    }

    @Override
    protected LastSignedInBackfillResponse buildEarlyExitResponse(
            LastSignedInBackfillRequest request) {
        long processedCount = getProcessedCountFromRequest(request);
        long updatedCount =
                request != null && request.updatedCount() != null ? request.updatedCount() : 0L;
        long skippedCount =
                request != null && request.skippedCount() != null ? request.skippedCount() : 0L;
        return new LastSignedInBackfillResponse(processedCount, updatedCount, skippedCount);
    }

    @Override
    protected SegmentResult processSegment(
            int segment,
            int totalSegments,
            int maxItemsPerSegment,
            Map<String, AttributeValue> exclusiveStartKey) {
        ScanSegmentResult result =
                scanSegment(segment, totalSegments, maxItemsPerSegment, exclusiveStartKey);
        invocationUpdatedCount.addAndGet(result.updatedCount());
        invocationSkippedCount.addAndGet(result.skippedCount());
        return new SegmentResult(result.itemsScanned(), result.lastEvaluatedKey());
    }

    ScanSegmentResult scanSegment(
            int segment,
            int totalSegments,
            int maxItemsPerSegment,
            Map<String, AttributeValue> exclusiveStartKey) {
        Map<String, AttributeValue> lastKey = exclusiveStartKey;
        long itemsScanned = 0;
        long updatedCount = 0;
        long skippedCount = 0;

        do {
            if (itemsScanned >= maxItemsPerSegment) {
                break;
            }

            ScanRequest.Builder requestBuilder =
                    ScanRequest.builder()
                            .tableName(trackerTableName)
                            .segment(segment)
                            .totalSegments(totalSegments)
                            .limit(maxItemsPerSegment)
                            .projectionExpression(LastSignedInBackfillHelper.TRACKER_PROJECTION);

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

                var fields = LastSignedInBackfillHelper.extractValidFields(item);
                if (fields.isEmpty()) {
                    LastSignedInBackfillHelper.logInvalidTrackerFields(item);
                    skippedCount++;
                    continue;
                }

                try {
                    client.updateItem(
                            LastSignedInBackfillHelper.buildConditionalUpdateRequest(
                                    userProfileTableName,
                                    fields.get().email(),
                                    fields.get().userLastActive()));
                    updatedCount++;
                } catch (ConditionalCheckFailedException e) {
                    skippedCount++;
                }
            }

            lastKey = response.lastEvaluatedKey();
        } while (lastKey != null && !lastKey.isEmpty());

        Map<String, AttributeValue> finalKey =
                (lastKey != null && !lastKey.isEmpty()) ? lastKey : null;

        LOG.info(
                "Segment {} complete: itemsScanned={}, updated={}, skipped={}, exhausted={}",
                segment,
                itemsScanned,
                updatedCount,
                skippedCount,
                finalKey == null);

        return new ScanSegmentResult(itemsScanned, updatedCount, skippedCount, finalKey);
    }

    record ScanSegmentResult(
            long itemsScanned,
            long updatedCount,
            long skippedCount,
            Map<String, AttributeValue> lastEvaluatedKey) {}
}
