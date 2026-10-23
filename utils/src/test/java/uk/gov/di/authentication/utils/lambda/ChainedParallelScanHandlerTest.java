package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.google.gson.annotations.Expose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.utils.exceptions.ChainedParallelScanException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class ChainedParallelScanHandlerTest {

    private final LambdaInvokerService lambdaInvokerService = mock(LambdaInvokerService.class);
    private final Context context = mock(Context.class);

    private StubHandler handler;

    @BeforeEach
    void setUp() {
        handler = new StubHandler(lambdaInvokerService);
    }

    @Test
    void handleRequestShouldThrowWhenMaxItemsPerSegmentIsZero() {
        handler.maxItemsPerSegment = 0;

        assertThrows(IllegalStateException.class, () -> handler.handleRequest(null));
    }

    @Test
    void handleRequestShouldReturnEarlyWhenMaxInvocationsExceeded() {
        handler.maxInvocations = 3;

        var request = new StubRequest(null, 100L, 3L);
        var response = handler.handleRequest(request);

        assertEquals(100L, response.processedCount());
        verify(lambdaInvokerService, never()).invokeAsyncWithPayload(any(), any());
    }

    @Test
    void handleRequestShouldAllowInvocationOneBelowMaxInvocationsLimit() {
        handler.maxInvocations = 3;
        handler.segmentResult = new ChainedParallelScanHandler.SegmentResult(5L, null);

        var request = new StubRequest(null, 0L, 2L);
        var response = handler.handleRequest(request);

        assertEquals(5L, response.processedCount());
    }

    @Test
    void handleRequestShouldProcessNullRequestAsFirstInvocation() {
        handler.segmentResult = new ChainedParallelScanHandler.SegmentResult(10L, null);

        var response = handler.handleRequest(null);

        assertEquals(10L, response.processedCount());
    }

    @Test
    void handleRequestShouldAccumulateProcessedCountFromPreviousInvocations() {
        handler.segmentResult = new ChainedParallelScanHandler.SegmentResult(10L, null);

        var request = new StubRequest(null, 50L, 0L);
        var response = handler.handleRequest(request);

        assertEquals(60L, response.processedCount());
    }

    @Test
    void handleRequestShouldSelfInvokeWhenSegmentHasRemainingItems() {
        Map<String, AttributeValue> lastKey =
                Map.of("Email", AttributeValue.builder().s("last@example.com").build());
        handler.segmentResult = new ChainedParallelScanHandler.SegmentResult(5L, lastKey);

        handler.handleRequest(null);

        verify(lambdaInvokerService).invokeAsyncWithPayload(any(String.class), eq("stub-lambda"));
    }

    @Test
    void handleRequestShouldNotSelfInvokeWhenAllSegmentsExhausted() {
        handler.segmentResult = new ChainedParallelScanHandler.SegmentResult(5L, null);

        handler.handleRequest(null);

        verify(lambdaInvokerService, never()).invokeAsyncWithPayload(any(), any());
    }

    @Test
    void handleRequestShouldPassContinuationStateToSelfInvoke() {
        Map<String, AttributeValue> lastKey =
                Map.of("Email", AttributeValue.builder().s("last@example.com").build());
        handler.segmentResult = new ChainedParallelScanHandler.SegmentResult(5L, lastKey);

        var request = new StubRequest(null, 100L, 2L);
        handler.handleRequest(request);

        var payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(lambdaInvokerService).invokeAsyncWithPayload(payloadCaptor.capture(), any());

        String payload = payloadCaptor.getValue();
        assertNotNull(payload);
        assert payload.contains("105");
        assert payload.contains("3");
    }

    @Test
    void handleRequestShouldThrowWhenLambdaNameNotConfiguredAndSegmentsRemain() {
        Map<String, AttributeValue> lastKey =
                Map.of("Email", AttributeValue.builder().s("last@example.com").build());
        handler.segmentResult = new ChainedParallelScanHandler.SegmentResult(5L, lastKey);
        handler.lambdaName = "";

        assertThrows(ChainedParallelScanException.class, () -> handler.handleRequest(null));
    }

    @Test
    void handleRequestShouldThrowWhenSelfInvocationFails() {
        Map<String, AttributeValue> lastKey =
                Map.of("Email", AttributeValue.builder().s("last@example.com").build());
        handler.segmentResult = new ChainedParallelScanHandler.SegmentResult(5L, lastKey);

        doThrow(new RuntimeException("Invoke failed"))
                .when(lambdaInvokerService)
                .invokeAsyncWithPayload(any(), any());

        assertThrows(ChainedParallelScanException.class, () -> handler.handleRequest(null));
    }

    @Test
    void handleRequestViaStreamShouldPreserveProcessedAndInvocationCountAcrossInvocations()
            throws Exception {
        Map<String, AttributeValue> lastKey =
                Map.of("Email", AttributeValue.builder().s("last@example.com").build());
        handler.segmentResult = new ChainedParallelScanHandler.SegmentResult(5L, lastKey);

        String incomingPayload =
                SerializationService.getInstance()
                        .writeValueAsString(new StubRequest(null, 100L, 2L));

        var inputStream =
                new ByteArrayInputStream(incomingPayload.getBytes(StandardCharsets.UTF_8));
        var outputStream = new ByteArrayOutputStream();

        handler.handleRequest(inputStream, outputStream, context);

        var payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(lambdaInvokerService).invokeAsyncWithPayload(payloadCaptor.capture(), any());

        StubRequest continuation =
                SerializationService.getInstance()
                        .readValue(payloadCaptor.getValue(), StubRequest.class);

        assertEquals(
                105L,
                continuation.processedCount(),
                "Expected processedCount to have been carried forward.");
        assertEquals(
                3L,
                continuation.invocationCount(),
                "Expected invocationCount to have been incremented, rather than reset.");

        StubResponse response =
                SerializationService.getInstance()
                        .readValue(
                                outputStream.toString(StandardCharsets.UTF_8), StubResponse.class);
        assertEquals(105L, response.processedCount());
    }

    @Test
    void handleRequestShouldOnlyScanSegmentsFromContinuationKeys() {
        handler.totalSegments = 4;
        handler.segmentResult = new ChainedParallelScanHandler.SegmentResult(5L, null);

        Map<Integer, Map<String, String>> segmentKeys = new HashMap<>();
        segmentKeys.put(2, Map.of("Email", "resume@example.com"));
        var request = new StubRequest(segmentKeys, 0L, 0L);

        handler.handleRequest(request);

        assertEquals(1, handler.processSegmentCallCount);
    }

    @Test
    void handleRequestShouldScanAllSegmentsOnFirstInvocation() {
        handler.totalSegments = 3;
        handler.segmentResult = new ChainedParallelScanHandler.SegmentResult(5L, null);

        handler.handleRequest(null);

        assertEquals(3, handler.processSegmentCallCount);
    }

    record StubRequest(
            @Expose Map<Integer, Map<String, String>> segmentKeys,
            @Expose Long processedCount,
            @Expose Long invocationCount) {}

    record StubResponse(@Expose long processedCount) {}

    static class StubHandler extends ChainedParallelScanHandler<StubRequest, StubResponse> {

        int maxInvocations = 1000;
        int parallelism = 2;
        int totalSegments = 1;
        int maxItemsPerSegment = 100;
        long pauseBetweenInvocationsMs = 0;
        String lambdaName = "stub-lambda";
        SegmentResult segmentResult = new SegmentResult(0L, null);
        int processSegmentCallCount = 0;

        StubHandler(LambdaInvokerService lambdaInvokerService) {
            super(lambdaInvokerService);
        }

        @Override
        protected Class<StubRequest> getRequestClass() {
            return StubRequest.class;
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
        protected Map<Integer, Map<String, String>> getSegmentKeysFromRequest(StubRequest request) {
            return request != null ? request.segmentKeys() : null;
        }

        @Override
        protected long getProcessedCountFromRequest(StubRequest request) {
            return request != null && request.processedCount() != null
                    ? request.processedCount()
                    : 0L;
        }

        @Override
        protected long getInvocationCountFromRequest(StubRequest request) {
            return request != null && request.invocationCount() != null
                    ? request.invocationCount()
                    : 0L;
        }

        @Override
        protected synchronized SegmentResult processSegment(
                int segment,
                int totalSegments,
                int maxItemsPerSegment,
                Map<String, AttributeValue> exclusiveStartKey) {
            processSegmentCallCount++;
            return segmentResult;
        }

        @Override
        protected StubRequest buildContinuationRequest(
                Map<Integer, Map<String, String>> remainingSegmentKeys,
                long processedCount,
                long invocationCount) {
            return new StubRequest(remainingSegmentKeys, processedCount, invocationCount);
        }

        @Override
        protected StubResponse buildResponse(long processedCount) {
            return new StubResponse(processedCount);
        }
    }
}
