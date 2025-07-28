package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvocationType;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.LambdaException;

import java.util.Optional;

public class LambdaInvokerService implements LambdaInvoker {
    private static final Logger LOG = LogManager.getLogger(LambdaInvokerService.class);
    public static final String MISSING = "missing";
    private final LambdaClient lambdaClient;

    public LambdaInvokerService(LambdaClient lambdaClient) {
        this.lambdaClient = lambdaClient;
    }

    public LambdaInvokerService(ConfigurationService configurationService) {
        this.lambdaClient =
                LambdaClient.builder()
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .region(Region.of(configurationService.getAwsRegion()))
                        .build();
    }

    @Override
    public void invokeAsyncWithPayload(String jsonPayload, String lambdaName) {
        SdkBytes payload;

        try {
            payload = SdkBytes.fromUtf8String(jsonPayload);
        } catch (Exception e) {
            LOG.error(
                    "Could not convert payload for {} into SdkBytes: {}", lambdaName, jsonPayload);
            return;
        }

        InvokeRequest invokeRequest =
                InvokeRequest.builder()
                        .functionName(lambdaName)
                        .invocationType(InvocationType.EVENT)
                        .payload(payload)
                        .build();

        try {
            lambdaClient.invoke(invokeRequest);
        } catch (LambdaException e) {
            var errorMessage =
                    Optional.ofNullable(e.awsErrorDetails())
                            .map(AwsErrorDetails::errorMessage)
                            .orElse(MISSING);

            var errorCode =
                    Optional.ofNullable(e.awsErrorDetails())
                            .map(AwsErrorDetails::errorCode)
                            .orElse(MISSING);

            var requestId = Optional.ofNullable(e.requestId()).orElse(MISSING);

            LOG.error(
                    "Lambda {} invocation error: {}\n Error code: {}\n Request ID: {}",
                    lambdaName,
                    errorMessage,
                    errorCode,
                    requestId);
        } catch (Exception e) {
            LOG.error("Lambda {} invocation failed in unexpected way: ", lambdaName, e);
        }
    }
}
