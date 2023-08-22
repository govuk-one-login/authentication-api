package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import uk.gov.di.authentication.shared.serialization.Json;

import java.nio.charset.StandardCharsets;

public class LambdaInvokerService implements LambdaInvoker {

    protected final Json objectMapper = SerializationService.getInstance();

    private final ConfigurationService configurationService;

    private final LambdaClient lambdaClient;

    public LambdaInvokerService(
            ConfigurationService configurationService, LambdaClient lambdaClient) {
        this.configurationService = configurationService;
        this.lambdaClient = lambdaClient;
    }

    public LambdaInvokerService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.lambdaClient =
                LambdaClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.create())
                        .region(Region.of(configurationService.getAwsRegion()))
                        .build();
    }

    @Override
    public void invokeWithPayload(ScheduledEvent scheduledEvent) {
        try {
            SdkBytes payload =
                    SdkBytes.fromByteArray(
                            objectMapper
                                    .writeValueAsString(scheduledEvent)
                                    .getBytes(StandardCharsets.UTF_8));

            InvokeRequest invokeRequest =
                    InvokeRequest.builder()
                            .functionName("BULK_USER_EMAIL_AUDIENCE_LOADER")
                            .payload(payload)
                            .build();
            lambdaClient.invoke(invokeRequest);

        } catch (Json.JsonException e) {
            throw new RuntimeException(e);
        }
    }
}
