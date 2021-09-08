package uk.gov.di.lambdawarmer.lambda;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LambdaWarmerHandlerTest {

    private final AWSLambda lambda = mock(AWSLambda.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final Context context = mock(Context.class);

    @Test
    void shouldExecuteTheSpecifiedNumberOfTimes() {
        when(configurationService.getLambdaArn()).thenReturn("a-function-arn");
        when(configurationService.getMinConcurrency()).thenReturn(5);
        when(lambda.invoke(any(InvokeRequest.class)))
                .thenReturn(
                        new InvokeResult()
                                .withPayload(
                                        ByteBuffer.wrap(
                                                "test-result".getBytes(StandardCharsets.UTF_8))));

        LambdaWarmerHandler handler = new LambdaWarmerHandler(configurationService, lambda);

        handler.handleRequest(new ScheduledEvent(), context);

        verify(lambda, times(5)).invoke(any(InvokeRequest.class));
    }

    void shouldExecuteTheDefaultNumberOfTimes() {
        when(configurationService.getLambdaArn()).thenReturn("a-function-arn");
        when(lambda.invoke(any(InvokeRequest.class)))
                .thenReturn(
                        new InvokeResult()
                                .withPayload(
                                        ByteBuffer.wrap(
                                                "test-result".getBytes(StandardCharsets.UTF_8))));

        LambdaWarmerHandler handler = new LambdaWarmerHandler(configurationService, lambda);

        handler.handleRequest(new ScheduledEvent(), context);

        verify(lambda, times(15)).invoke(any(InvokeRequest.class));
    }
}
