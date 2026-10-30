package uk.gov.di.authentication.local.initialisers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.CreateQueueRequest;

public class SqsInitialiser {
    private static final Logger LOG = LogManager.getLogger(SqsInitialiser.class);
    private static final int MAX_ATTEMPTS = 10;
    private static final long RETRY_DELAY_MILLIS = 1000;

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
        RuntimeException lastError = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                sqsClient.createQueue(
                        CreateQueueRequest.builder().queueName(queueName).build());
                return;
            } catch (RuntimeException e) {
                lastError = e;
                LOG.warn(
                        "Failed to create SQS queue {} (attempt {}/{}): {}",
                        queueName,
                        attempt,
                        MAX_ATTEMPTS,
                        e.getMessage());
                if (attempt < MAX_ATTEMPTS) {
                    sleep();
                }
            }
        }
        throw new IllegalStateException(
                "Unable to create SQS queue " + queueName + " after " + MAX_ATTEMPTS + " attempts",
                lastError);
    }

    private void sleep() {
        try {
            Thread.sleep(RETRY_DELAY_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting to retry queue creation", e);
        }
    }
}
