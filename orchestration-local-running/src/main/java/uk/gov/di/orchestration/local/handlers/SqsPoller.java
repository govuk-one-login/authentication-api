package uk.gov.di.orchestration.local.handlers;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.ReceiveMessageResponse;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;

public class SqsPoller extends Thread {
    private static final Logger LOG = LogManager.getLogger(SqsPoller.class);
    private static final LocalLambdaContext LAMBDA_CONTEXT = new LocalLambdaContext();

    private final String queueUrl;
    private final RequestHandler<SQSEvent, Object> handler;
    private final SqsClient sqsClient;

    public static void startAsyncPoll(String queueUrl, RequestHandler<SQSEvent, Object> handler) {
        var sqsPoller = new SqsPoller(queueUrl, handler);
        sqsPoller.setDaemon(true);
        sqsPoller.start();
    }

    public SqsPoller(String queueUrl, RequestHandler<SQSEvent, Object> handler) {
        var configurationService = ConfigurationService.getInstance();
        this.queueUrl = queueUrl;
        this.handler = handler;
        var sqsClientBuilder =
                SqsClient.builder()
                        .region(Region.of(configurationService.getAwsRegion()))
                        .credentialsProvider(DefaultCredentialsProvider.builder().build());
        configurationService
                .getSqsEndpointURI()
                .ifPresent(s -> sqsClientBuilder.endpointOverride(URI.create(s)));
        this.sqsClient = sqsClientBuilder.build();
    }

    @Override
    public void run() {
        LOG.info("SQS poller starting up");
        while (true) {
            try {
                poll();
            } catch (InterruptedException _) {
                LOG.error("SQS poller interrupted");
                this.interrupt();
                break;
            }
        }
    }

    private void poll() throws InterruptedException {
        try {
            var response =
                    sqsClient.receiveMessage(
                            (builder) -> builder.queueUrl(queueUrl).waitTimeSeconds(5));

            if (response.hasMessages()) {
                handler.handleRequest(mapToSQSEvent(response), LAMBDA_CONTEXT);

                for (var message : response.messages()) {
                    sqsClient.deleteMessage(
                            (builder) ->
                                    builder.queueUrl(queueUrl)
                                            .receiptHandle(message.receiptHandle()));
                }
            }
        } catch (SdkClientException e) {
            LOG.error("Encountered error polling SQS", e);
            throw new InterruptedException("Failed polling SQS");
        }
    }

    private SQSEvent mapToSQSEvent(ReceiveMessageResponse response) {
        var event = new SQSEvent();
        event.setRecords(response.messages().stream().map(this::mapToSQSMessage).toList());
        return event;
    }

    private SQSEvent.SQSMessage mapToSQSMessage(Message message) {
        var sqsMessage = new SQSEvent.SQSMessage();
        sqsMessage.setMessageId(message.messageId());
        sqsMessage.setReceiptHandle(message.receiptHandle());
        sqsMessage.setBody(message.body());
        sqsMessage.setMd5OfBody(message.md5OfBody());
        sqsMessage.setAttributes(message.attributesAsStrings());
        // TODO: If we start using message attributes they need to be mapped properly
        // sqsMessage.setMessageAttributes(message.messageAttributes());
        sqsMessage.setMd5OfMessageAttributes(message.md5OfMessageAttributes());
        sqsMessage.setEventSource("aws:sqs");
        sqsMessage.setEventSourceArn("arn:aws:sqs:local:example");
        sqsMessage.setAwsRegion("eu-west-2");
        return sqsMessage;
    }
}
