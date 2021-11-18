package uk.gov.di.authentication.frontendapi.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.SqsClientBuilder;
import software.amazon.awssdk.services.sqs.model.GetQueueAttributesRequest;
import software.amazon.awssdk.services.sqs.model.PurgeQueueRequest;
import software.amazon.awssdk.services.sqs.model.QueueAttributeName;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;

import java.net.URI;
import java.util.Optional;

import static java.lang.Thread.sleep;

public class AwsSqsClient {

    private static final Logger LOG = LoggerFactory.getLogger(AwsSqsClient.class);

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

    public String send(final String event) throws SdkClientException {
        SendMessageRequest messageRequest =
                SendMessageRequest.builder().queueUrl(queueUrl).messageBody(event).build();

        var result = client.sendMessage(messageRequest);
        return result.messageId();
    }

    public void purge() {
        GetQueueAttributesRequest attributesRequest =
                GetQueueAttributesRequest.builder()
                        .queueUrl(queueUrl)
                        .attributeNames(QueueAttributeName.APPROXIMATE_NUMBER_OF_MESSAGES)
                        .build();
        var result = client.getQueueAttributes(attributesRequest);
        result.getValueForField(
                        QueueAttributeName.APPROXIMATE_NUMBER_OF_MESSAGES.name(), Integer.class)
                .ifPresent(
                        count -> {
                            LOG.info("Found {} messages in the queue", count);
                            if (count > 0) {
                                PurgeQueueRequest request =
                                        PurgeQueueRequest.builder().queueUrl(queueUrl).build();
                                client.purgeQueue(request);
                            }
                            try {
                                sleep(60000);
                            } catch (InterruptedException ignored) {

                            }
                        });
    }
}
