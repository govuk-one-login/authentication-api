package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.SqsClientBuilder;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;

import java.net.URI;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class AwsSqsClient {

    private static Logger LOG = LogManager.getLogger(AwsSqsClient.class);

    private final SqsClient client;
    private final String queueUrl;

    public AwsSqsClient(String region, String queueUrl, Optional<String> sqsEndpoint) {
        SqsClientBuilder amazonSqsBuilder = SqsClient.builder().region(Region.of(region));

        if (sqsEndpoint.isPresent()) {
            amazonSqsBuilder
                    .endpointOverride(URI.create(sqsEndpoint.get()))
                    .credentialsProvider(
                            StaticCredentialsProvider.create(
                                    AwsBasicCredentials.create("FAKEACCESSKEY", "FAKESECRETKEY")));
        }
        this.client = amazonSqsBuilder.build();
        this.queueUrl = queueUrl;
    }

    public void send(final String event) throws SdkClientException {
        SendMessageRequest messageRequest =
                SendMessageRequest.builder().queueUrl(queueUrl).messageBody(event).build();

        client.sendMessage(messageRequest);
    }

    public <T> void sendAsync(final T message) throws SdkClientException {
        CompletableFuture.runAsync(
                () -> {
                    try {
                        send(Json.jackson().writeValueAsString(message));
                    } catch (JsonException e) {
                        LOG.error("Unable to serialise SQS message: " + message);
                    }
                });
    }
}
