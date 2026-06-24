package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.SqsClientBuilder;
import software.amazon.awssdk.services.sqs.model.GetQueueAttributesRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;

import java.net.URI;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class AwsSqsClient {

    private final SqsClient client;
    private final String queueUrl;
    private static final Logger LOG = LogManager.getLogger(AwsSqsClient.class);

    public AwsSqsClient(String region, String queueUrl, Optional<String> sqsEndpoint) {
        SqsClientBuilder amazonSqsBuilder = SqsClient.builder().region(Region.of(region));

        if (sqsEndpoint.isPresent()) {
            amazonSqsBuilder
                    .endpointOverride(URI.create(sqsEndpoint.get()))
                    .credentialsProvider(EnvironmentVariableCredentialsProvider.create());
        }
        this.client = amazonSqsBuilder.build();
        this.queueUrl = queueUrl;
        warmUp(queueUrl);
    }

    protected AwsSqsClient(SqsClient client, String queueUrl) {
        this.client = client;
        this.queueUrl = queueUrl;
    }

    public void send(final String event) throws SdkClientException {
        SendMessageRequest messageRequest =
                SendMessageRequest.builder().queueUrl(queueUrl).messageBody(event).build();

        client.sendMessage(messageRequest);
    }

    public <T> void sendAsync(final T message) throws SdkClientException {
        CompletableFuture.runAsync(
                () -> send(SerializationService.getInstance().writeValueAsString(message)));
    }

    private void warmUp(String queueUrl) {
        try {
            client.getQueueAttributes(
                    GetQueueAttributesRequest.builder().queueUrl(queueUrl).build());
        } catch (Exception e) {
            LOG.warn("Failed to getQueueAttributes for queue: {}", e.getMessage());
        }
    }
}
