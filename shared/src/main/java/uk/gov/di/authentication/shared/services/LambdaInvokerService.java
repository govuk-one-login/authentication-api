package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import net.minidev.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvocationType;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import uk.gov.di.authentication.shared.exceptions.LambdaInvokerServiceException;
import uk.gov.di.authentication.shared.serialization.Json;

public class LambdaInvokerService implements LambdaInvoker {

    private static final Logger LOG = LogManager.getLogger(LambdaInvokerService.class);

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
        String lambdaName = configurationService.getBulkEmailLoaderLambdaName();

        if (lambdaName == null || lambdaName.isEmpty()) {
            throw new LambdaInvokerServiceException(
                    "BULK_USER_EMAIL_AUDIENCE_LOADER_LAMBDA_NAME environment variable not set");
        }

        JSONObject detail = new JSONObject();
        detail.appendField("lastEvaluatedKey", scheduledEvent.getDetail().get("lastEvaluatedKey"));
        detail.appendField(
                "globalUsersAddedCount", scheduledEvent.getDetail().get("globalUsersAddedCount"));

        String jsonPayload = new JSONObject().appendField("detail", detail).toJSONString();
        SdkBytes payload = SdkBytes.fromUtf8String(jsonPayload);

        InvokeRequest invokeRequest =
                InvokeRequest.builder()
                        .functionName(lambdaName)
                        .invocationType(InvocationType.EVENT)
                        .payload(payload)
                        .build();
        lambdaClient.invoke(invokeRequest);
    }
}
