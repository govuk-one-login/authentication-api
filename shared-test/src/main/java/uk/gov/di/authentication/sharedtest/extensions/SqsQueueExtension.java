package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
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
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

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
                        .endpointOverride(LOCALSTACK_ENDPOINT)
                        .credentialsProvider(LOCALSTACK_CREDENTIALS_PROVIDER)
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
        return getMessages(DEFAULT_NUMBER_OF_MESSAGES).stream()
                .map(Message::body)
                .collect(Collectors.toList());
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
                .collect(Collectors.toList());
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        var queueName =
                format(
                        "{0}-{1}",
                        context.getTestClass().map(Class::getSimpleName).orElse("unknown"),
                        queueNameSuffix);
        var truncatedQueueName = queueName.substring(0, Math.min(80, queueName.length()));
        queueUrl =
                getQueueUrlFor(truncatedQueueName).orElseGet(() -> createQueue(truncatedQueueName));
        sqsClient.purgeQueue(PurgeQueueRequest.builder().queueUrl(queueUrl).build());
    }

    private Optional<String> getQueueUrlFor(String queueName) {
        try {
            return Optional.of(
                    sqsClient
                            .getQueueUrl(GetQueueUrlRequest.builder().queueName(queueName).build())
                            .toString());
        } catch (QueueDoesNotExistException ignored) {
            return Optional.empty();
        }
    }

    private String createQueue(String queueName) {
        return sqsClient
                .createQueue(CreateQueueRequest.builder().queueName(queueName).build())
                .queueUrl();
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
