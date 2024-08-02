package uk.gov.di.accountmanagement.services;

import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.SqsClientBuilder;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;

import java.net.URI;
import java.util.Optional;

public class AwsSqsClient {

    private final SqsClient client;
    private final String queueUrl;

    public AwsSqsClient(String region, String queueUrl, Optional<String> sqsEndpoint) {
        SqsClientBuilder amazonSqsBuilder = SqsClient.builder().region(Region.of(region));

        sqsEndpoint.ifPresent(
                s ->
                        amazonSqsBuilder
                                .endpointOverride(URI.create(s))
                                .credentialsProvider(
                                        EnvironmentVariableCredentialsProvider.create()));
        this.client = amazonSqsBuilder.build();
        this.queueUrl = queueUrl;
    }

    public void send(final String event) throws SdkClientException {
        SendMessageRequest messageRequest =
                SendMessageRequest.builder().queueUrl(queueUrl).messageBody(event).build();

        client.sendMessage(messageRequest);
    }
}
