package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClient;
import com.amazonaws.services.sqs.model.Message;
import com.amazonaws.services.sqs.model.PurgeQueueRequest;
import com.amazonaws.services.sqs.model.QueueDoesNotExistException;
import com.amazonaws.services.sqs.model.ReceiveMessageRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.text.MessageFormat.format;

public class SqsQueueExtension extends BaseAwsResourceExtension implements BeforeAllCallback {

    public static final int DEFAULT_NUMBER_OF_MESSAGES = 10;

    private final String queueNameSuffix;
    private final AmazonSQS sqsClient;
    private final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

    private String queueUrl;

    public SqsQueueExtension(String queueNameSuffix) {
        this.queueNameSuffix = queueNameSuffix;
        this.sqsClient =
                AmazonSQSClient.builder()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(
                                        LOCALSTACK_ENDPOINT, REGION))
                        .build();
    }

    public String getQueueUrl() {
        return queueUrl;
    }

    public <T> List<T> getMessages(Class<T> messageClass) {
        return getMessages(messageClass, DEFAULT_NUMBER_OF_MESSAGES);
    }

    public <T> List<T> getMessages(Class<T> messageClass, int numberOfMessages) {
        return getMessages(numberOfMessages).stream()
                .map(
                        m -> {
                            try {
                                return objectMapper.readValue(m.getBody(), messageClass);
                            } catch (JsonProcessingException e) {
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

    private List<Message> getMessages(int numberOfMessages) {
        var request =
                new ReceiveMessageRequest()
                        .withQueueUrl(queueUrl)
                        .withMaxNumberOfMessages(numberOfMessages);
        return sqsClient.receiveMessage(request).getMessages();
    }
}
