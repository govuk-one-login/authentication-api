package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvocationType;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.LambdaException;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessage;

class LambdaInvokerServiceTest {
    String functionName = "SOME_FUNCTION_NAME";
    String payloadString = "{\"foo\": \"bar\"}";
    SdkBytes payload = SdkBytes.fromUtf8String(payloadString);
    InvokeRequest expectedInvokeRequest =
            InvokeRequest.builder()
                    .functionName(functionName)
                    .invocationType(InvocationType.EVENT)
                    .payload(payload)
                    .build();

    LambdaClient lambdaClient;
    LambdaInvokerService lambdaInvokerService;

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(LambdaInvokerService.class);

    @BeforeEach
    void beforeEach() {
        lambdaClient = mock(LambdaClient.class);
        lambdaInvokerService = new LambdaInvokerService(lambdaClient);
    }

    @Test
    void shouldInvokeTheSpecifiedLambdaWithTheGivenPayload() {
        assertDoesNotThrow(
                () -> lambdaInvokerService.invokeAsyncWithPayload(payloadString, functionName));

        verify(lambdaClient).invoke(expectedInvokeRequest);
    }

    @Test
    void shouldNotAllowExpectedExceptionsToEscape() {
        when(lambdaClient.invoke((InvokeRequest) any())).thenThrow(mock(LambdaException.class));

        assertDoesNotThrow(
                () -> lambdaInvokerService.invokeAsyncWithPayload(payloadString, functionName));
    }

    @Test
    void shouldNotAllowUnexpectedExceptionsToEscape() {
        when(lambdaClient.invoke((InvokeRequest) any())).thenThrow(mock(RuntimeException.class));

        assertDoesNotThrow(
                () -> lambdaInvokerService.invokeAsyncWithPayload(payloadString, functionName));
    }

    @Test
    void checkConstructor() {
        var mockConfigurationService = mock(ConfigurationService.class);
        when(mockConfigurationService.getAwsRegion()).thenReturn("eu-west-2");

        assertDoesNotThrow(() -> new LambdaInvokerService(mockConfigurationService));

        verify(mockConfigurationService).getAwsRegion();
    }

    @Test
    void checkHandlesPayloadsThatDontConvertToSdkBytes() {
        assertDoesNotThrow(() -> lambdaInvokerService.invokeAsyncWithPayload(null, functionName));
        assertThat(
                logging.events(),
                hasItem(withMessage("Could not convert payload for TICF CRI into SdkBytes: null")));
    }
}
