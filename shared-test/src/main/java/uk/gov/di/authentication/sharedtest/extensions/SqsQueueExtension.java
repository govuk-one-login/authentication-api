package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClient;
import com.amazonaws.services.sqs.model.PurgeQueueRequest;
import com.amazonaws.services.sqs.model.QueueDoesNotExistException;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Optional;

public class SqsQueueExtension implements BeforeAllCallback {

    protected static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    protected static final String LOCALSTACK_ENDPOINT =
            System.getenv().getOrDefault("LOCALSTACK_ENDPOINT", "http://localhost:45678");

    private final String queueName;
    private final AmazonSQS sqsClient;

    private String queueUrl;

    public SqsQueueExtension(String queueName) {
        this.queueName = queueName;
        this.sqsClient =
                AmazonSQSClient.builder()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(
                                        LOCALSTACK_ENDPOINT, REGION))
                        .build();
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        queueUrl = getQueueUrlFor(queueName).orElseGet(() -> createQueue(queueName));
        sqsClient.purgeQueue(new PurgeQueueRequest().withQueueUrl(queueUrl));
    }

    private Optional<String> getQueueUrlFor(String queueName) {
        try {
            return Optional.of(sqsClient.getQueueUrl(queueName).getQueueUrl());
        } catch (QueueDoesNotExistException ignored) {
            return Optional.empty();
        }
    }

    private String createQueue(String queueName) {
        return sqsClient.createQueue(queueName).getQueueUrl();
    }
}
