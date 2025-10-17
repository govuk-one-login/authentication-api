package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.CreateQueueRequest;
import software.amazon.awssdk.services.sqs.model.GetQueueAttributesRequest;
import software.amazon.awssdk.services.sqs.model.GetQueueUrlRequest;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.PurgeQueueRequest;
import software.amazon.awssdk.services.sqs.model.QueueAttributeName;
import software.amazon.awssdk.services.sqs.model.QueueDoesNotExistException;
import software.amazon.awssdk.services.sqs.model.ReceiveMessageRequest;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.net.URI;
import java.util.List;

import static java.text.MessageFormat.format;

public class SqsQueueExtension extends BaseAwsResourceExtension implements BeforeAllCallback {

    public static final int DEFAULT_NUMBER_OF_MESSAGES = 10;

    private final String queueNameSuffix;
    private final SqsClient sqsClient;
    private final Json objectMapper = SerializationService.getInstance();

    private String queueUrl;

    public SqsQueueExtension(String queueNameSuffix) {
        this.queueNameSuffix = queueNameSuffix;
        this.sqsClient =
                SqsClient.builder()
                        .endpointOverride(URI.create(LOCALSTACK_ENDPOINT))
                        .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
                        .region(Region.of(REGION))
                        .build();
    }

    public String getQueueUrl() {
        return queueUrl;
    }

    public int getApproximateMessageCount() {
        var getQueueAttributesRequest =
                GetQueueAttributesRequest.builder()
                        .queueUrl(queueUrl)
                        .attributeNames(QueueAttributeName.APPROXIMATE_NUMBER_OF_MESSAGES)
                        .build();
        var result = sqsClient.getQueueAttributes(getQueueAttributesRequest);
        var countString =
                result.attributes().get(QueueAttributeName.APPROXIMATE_NUMBER_OF_MESSAGES);

        return Integer.parseInt(countString);
    }

    public <T> List<T> getMessages(Class<T> messageClass) {
        return getMessages(messageClass, DEFAULT_NUMBER_OF_MESSAGES);
    }

    public List<String> getRawMessages() {
        return getMessages(DEFAULT_NUMBER_OF_MESSAGES).stream().map(Message::body).toList();
    }

    public <T> List<T> getMessages(Class<T> messageClass, int numberOfMessages) {
        return getMessages(numberOfMessages).stream()
                .map(
                        m -> {
                            try {
                                return objectMapper.readValue(m.body(), messageClass);
                            } catch (Json.JsonException e) {
                                throw new RuntimeException(e);
                            }
                        })
                .toList();
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        var queueName =
                format(
                        "{0}-{1}",
                        context.getTestClass().map(Class::getSimpleName).orElse("unknown"),
                        queueNameSuffix);
        var truncatedQueueName = queueName.substring(0, Math.min(80, queueName.length()));

        // Always create a fresh queue to handle container recreation
        queueUrl = createQueue(truncatedQueueName);

        // Clear any existing messages
        try {
            sqsClient.purgeQueue(PurgeQueueRequest.builder().queueUrl(queueUrl).build());
        } catch (Exception e) {
            // Ignore purge errors as queue might be newly created
        }
    }

    private String createQueue(String queueName) {
        try {
            // Try to get existing queue first
            return sqsClient
                    .getQueueUrl(GetQueueUrlRequest.builder().queueName(queueName).build())
                    .queueUrl();
        } catch (QueueDoesNotExistException e) {
            // Create new queue if it doesn't exist
            return sqsClient
                    .createQueue(CreateQueueRequest.builder().queueName(queueName).build())
                    .queueUrl();
        }
    }

    private List<Message> getMessages(int numberOfMessages) {
        var request =
                ReceiveMessageRequest.builder()
                        .queueUrl(queueUrl)
                        .maxNumberOfMessages(numberOfMessages)
                        .build();
        return sqsClient.receiveMessage(request).messages();
    }

    public void clear() {
        sqsClient.purgeQueue(PurgeQueueRequest.builder().queueUrl(queueUrl).build());
    }
}
