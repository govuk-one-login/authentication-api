package uk.gov.di.authentication.local.initialisers;

import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.CreateQueueRequest;

import java.net.URI;

public class SqsInitialiser {
    private final SqsClient sqsClient;

    public SqsInitialiser() {
        this.sqsClient = SqsClient.builder()
                .endpointOverride(URI.create(System.getenv("LOCALSTACK_ENDPOINT")))
                .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
                .region(Region.of(System.getenv("AWS_REGION")))
                .build();
    }

    public void createQueue(String queueName) {
        sqsClient
                .createQueue(CreateQueueRequest.builder().queueName(queueName).build())
                .queueUrl();
    }
}
