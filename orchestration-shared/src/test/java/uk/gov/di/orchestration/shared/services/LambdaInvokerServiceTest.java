package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvocationType;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import uk.gov.di.orchestration.shared.serialization.Json;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LambdaInvokerServiceTest {

    ConfigurationService configurationService = mock(ConfigurationService.class);

    LambdaClient lambdaClient = mock(LambdaClient.class);

    ScheduledEvent scheduledEvent = mock(ScheduledEvent.class);

    @Test
    void shouldInvokeTheLambdaWithTheGivenScheduledEvent() {
        var functionName = "BULK_USER_EMAIL_AUDIENCE_LOADER";
        when(configurationService.getBulkEmailLoaderLambdaName()).thenReturn(functionName);
        var lastEvaluatedKey = "email@example.com";
        var globalUsersAddedCount = "5";
        Map<String, Object> details =
                Map.of(
                        "globalUsersAddedCount",
                        globalUsersAddedCount,
                        "lastEvaluatedKey",
                        lastEvaluatedKey);
        when(scheduledEvent.getDetail()).thenReturn(details);

        JSONObject detail =
                new JSONObject()
                        .appendField("lastEvaluatedKey", lastEvaluatedKey)
                        .appendField("globalUsersAddedCount", globalUsersAddedCount);
        String payloadString = new JSONObject().appendField("detail", detail).toJSONString();

        var payload = SdkBytes.fromUtf8String(payloadString);
        InvokeRequest invokeRequest =
                InvokeRequest.builder()
                        .functionName(functionName)
                        .invocationType(InvocationType.EVENT)
                        .payload(payload)
                        .build();
        LambdaInvokerService lambdaInvokerService =
                new LambdaInvokerService(configurationService, lambdaClient);

        lambdaInvokerService.invokeWithPayload(scheduledEvent);

        verify(lambdaClient).invoke(invokeRequest);
    }

    @Test
    void shouldThrowErrorWhenLambdaNameNotSetInEnvironment() throws Json.JsonException {
        when(configurationService.getBulkEmailLoaderLambdaName()).thenReturn("");
        LambdaInvokerService lambdaInvokerService =
                new LambdaInvokerService(configurationService, lambdaClient);

        assertThrows(
                RuntimeException.class,
                () -> lambdaInvokerService.invokeWithPayload(scheduledEvent),
                "BULK_USER_EMAIL_AUDIENCE_LOADER_LAMBDA_NAME environment variable not set");
    }
}
