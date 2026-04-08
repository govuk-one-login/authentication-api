package uk.gov.di.authentication.local.initialisers;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.CreateQueueRequest;

public class SqsInitialiser {
    private final SqsClient sqsClient;

    public SqsInitialiser() {
        this.sqsClient =
                SqsClient.builder()
                        .endpointOverride(InitialiserConfig.LOCALSTACK_ENDPOINT)
                        .region(InitialiserConfig.REGION)
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .build();
    }

    public void createQueue(String queueName) {
        sqsClient.createQueue(CreateQueueRequest.builder().queueName(queueName).build());
    }
}
