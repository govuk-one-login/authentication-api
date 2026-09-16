package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.helpers.LambdaPauseHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.utils.exceptions.ChainedParallelScanException;
import uk.gov.di.authentication.utils.helpers.ChainedParallelScanHelper;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;

public abstract class ChainedParallelScanHandler<TRequest, TResponse>
        implements RequestStreamHandler {

    private static final Logger LOG = LogManager.getLogger(ChainedParallelScanHandler.class);

    protected final Json objectMapper = SerializationService.getInstance();
    private final LambdaInvokerService lambdaInvokerService;

    protected ChainedParallelScanHandler(LambdaInvokerService lambdaInvokerService) {
        this.lambdaInvokerService = lambdaInvokerService;
    }

    protected abstract Class<TRequest> getRequestClass();

    protected abstract int getMaxInvocations();

    protected abstract int getParallelism();

    protected abstract int getTotalSegments();

    protected abstract int getMaxItemsPerSegment();

    protected abstract long getPauseBetweenInvocationsMs();

    protected abstract String getLambdaName();

    protected abstract Map<Integer, Map<String, String>> getSegmentKeysFromRequest(
            TRequest request);

    protected abstract long getProcessedCountFromRequest(TRequest request);

    protected abstract long getInvocationCountFromRequest(TRequest request);

    protected abstract SegmentResult processSegment(
            int segment,
            int totalSegments,
            int maxItemsPerSegment,
            Map<String, AttributeValue> exclusiveStartKey);

    protected abstract TRequest buildContinuationRequest(
            Map<Integer, Map<String, String>> remainingSegmentKeys,
            long processedCount,
            long invocationCount);

    protected abstract TResponse buildResponse(long processedCount);

    protected TResponse buildEarlyExitResponse(TRequest request) {
        return buildResponse(getProcessedCountFromRequest(request));
    }

    protected void beforeScan(TRequest request) {}

    protected void onMaxInvocationsExceeded(
            long invocationCount, long maxInvocations, long processedCount) {
        LOG.warn(
                "MAX_INVOCATIONS_EXCEEDED: invocationCount={} has reached or exceeded"
                        + " maxInvocations={}, halting self-invocation chain."
                        + " processedCount={}",
                invocationCount,
                maxInvocations,
                processedCount);
    }

    protected void onInvocationComplete(
            long processedThisInvocation, long totalProcessed, int segmentsRemaining) {
        LOG.info(
                "Invocation complete: processedThisInvocation={}, totalProcessed={},"
                        + " segmentsRemaining={}",
                processedThisInvocation,
                totalProcessed,
                segmentsRemaining);
    }

    @Override
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context)
            throws IOException {
        TRequest request = deserialiseRequest(inputStream);
        TResponse response = handleRequest(request);
        writeResponse(outputStream, response);
    }

    public final TResponse handleRequest(TRequest request) {
        if (getMaxItemsPerSegment() <= 0) {
            throw new IllegalStateException("maxItemsPerSegment must be greater than 0");
        }

        long processedCount = getProcessedCountFromRequest(request);
        long invocationCount = getInvocationCountFromRequest(request);

        if (invocationCount >= getMaxInvocations()) {
            onMaxInvocationsExceeded(invocationCount, getMaxInvocations(), processedCount);
            return buildEarlyExitResponse(request);
        }

        beforeScan(request);

        Map<Integer, Map<String, AttributeValue>> activeSegments =
                resolveActiveSegments(request, getTotalSegments());

        List<SegmentTask> segmentTasks = new ArrayList<>();
        ForkJoinPool forkJoinPool = new ForkJoinPool(getParallelism());

        try {
            for (var entry : activeSegments.entrySet()) {
                int segment = entry.getKey();
                Map<String, AttributeValue> startKey = entry.getValue();
                segmentTasks.add(
                        new SegmentTask(
                                segment,
                                forkJoinPool.submit(
                                        () ->
                                                processSegment(
                                                        segment,
                                                        getTotalSegments(),
                                                        getMaxItemsPerSegment(),
                                                        startKey))));
            }

            ChainedParallelScanHelper.gracefulPoolShutdown(forkJoinPool);

            long totalProcessed = 0;
            Map<Integer, Map<String, String>> remainingSegmentKeys = new HashMap<>();

            for (SegmentTask segmentTask : segmentTasks) {
                SegmentResult result = segmentTask.task().join();
                totalProcessed += result.itemsScanned();

                if (result.lastEvaluatedKey() != null && !result.lastEvaluatedKey().isEmpty()) {
                    remainingSegmentKeys.put(
                            segmentTask.segment(),
                            ChainedParallelScanHelper.toSerialisableKeys(
                                    result.lastEvaluatedKey()));
                }
            }

            processedCount += totalProcessed;

            onInvocationComplete(totalProcessed, processedCount, remainingSegmentKeys.size());

            if (!remainingSegmentKeys.isEmpty()) {
                selfInvoke(remainingSegmentKeys, processedCount, invocationCount);
            }

            return buildResponse(processedCount);
        } finally {
            ChainedParallelScanHelper.forcePoolShutdown(forkJoinPool);
        }
    }

    private TRequest deserialiseRequest(InputStream inputStream) throws IOException {
        String body = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        if (body.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readValue(body, getRequestClass());
        } catch (Json.JsonException e) {
            throw new ChainedParallelScanException("Failed to deserialise request", e);
        }
    }

    private void writeResponse(OutputStream outputStream, TResponse response) throws IOException {
        try {
            outputStream.write(
                    objectMapper.writeValueAsString(response).getBytes(StandardCharsets.UTF_8));
        } catch (Json.JsonException e) {
            throw new ChainedParallelScanException("Failed to serialise response", e);
        }
    }

    private Map<Integer, Map<String, AttributeValue>> resolveActiveSegments(
            TRequest request, int totalSegments) {
        Map<Integer, Map<String, AttributeValue>> activeSegments = new HashMap<>();
        Map<Integer, Map<String, String>> segmentKeys = getSegmentKeysFromRequest(request);

        if (segmentKeys == null) {
            for (int i = 0; i < totalSegments; i++) {
                activeSegments.put(i, null);
            }
        } else {
            for (var entry : segmentKeys.entrySet()) {
                activeSegments.put(
                        entry.getKey(), ChainedParallelScanHelper.toDynamoKeys(entry.getValue()));
            }
        }

        return activeSegments;
    }

    private void selfInvoke(
            Map<Integer, Map<String, String>> remainingSegmentKeys,
            long processedCount,
            long invocationCount) {
        String lambdaName = getLambdaName();
        if (lambdaName == null || lambdaName.isEmpty()) {
            throw new ChainedParallelScanException(
                    "Lambda name not configured, cannot self-invoke. "
                            + "Check your getLambdaName() configuration.");
        }

        LambdaPauseHelper.pauseBetweenInvocations(getPauseBetweenInvocationsMs());

        long nextInvocationCount = invocationCount + 1;

        TRequest continuationRequest =
                buildContinuationRequest(remainingSegmentKeys, processedCount, nextInvocationCount);

        String payload;
        try {
            payload = objectMapper.writeValueAsString(continuationRequest);
        } catch (Json.JsonException e) {
            throw new ChainedParallelScanException("Failed to serialise continuation request", e);
        }

        LOG.info(
                "Self-invoking with {} remaining segments, processedCount={}, invocationCount={}",
                remainingSegmentKeys.size(),
                processedCount,
                nextInvocationCount);

        try {
            lambdaInvokerService.invokeAsyncWithPayload(payload, lambdaName);
        } catch (Exception e) {
            LOG.error("Self-invocation failed", e);
            throw new ChainedParallelScanException(
                    "Failed to self-invoke lambda: " + lambdaName, e);
        }
    }

    public record SegmentTask(int segment, ForkJoinTask<SegmentResult> task) {}

    public record SegmentResult(long itemsScanned, Map<String, AttributeValue> lastEvaluatedKey) {}
}
