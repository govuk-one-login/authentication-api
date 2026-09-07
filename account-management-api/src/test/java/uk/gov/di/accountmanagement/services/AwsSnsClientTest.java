package uk.gov.di.accountmanagement.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;
import software.amazon.awssdk.services.sns.model.PublishResponse;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class AwsSnsClientTest {

    private static final String TOPIC_ARN = "arn:aws:sns:eu-west-2:123456789012:test-topic";
    private static final String MESSAGE = "test-message";
    private static final String MESSAGE_ID = "test-message-id-12345";

    private final SnsClient snsClient = mock(SnsClient.class);
    private final AwsSnsClient awsSnsClient = new AwsSnsClient(snsClient, TOPIC_ARN);

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(AwsSnsClient.class);

    @Test
    void shouldPublishMessageToSns() {
        var expectedRequest = PublishRequest.builder().message(MESSAGE).topicArn(TOPIC_ARN).build();
        when(snsClient.publish(expectedRequest))
                .thenReturn(PublishResponse.builder().messageId(MESSAGE_ID).build());

        awsSnsClient.publish(MESSAGE);

        verify(snsClient).publish(expectedRequest);
    }

    @Test
    void shouldLogMessageIdWhenPublishSucceeds() {
        var expectedRequest = PublishRequest.builder().message(MESSAGE).topicArn(TOPIC_ARN).build();
        when(snsClient.publish(expectedRequest))
                .thenReturn(PublishResponse.builder().messageId(MESSAGE_ID).build());

        awsSnsClient.publish(MESSAGE);

        assertThat(logging.events(), hasItem(withMessageContaining(MESSAGE_ID)));
    }

    @Test
    void shouldThrowSdkClientExceptionWhenPublishFails() {
        var expectedRequest = PublishRequest.builder().message(MESSAGE).topicArn(TOPIC_ARN).build();
        when(snsClient.publish(expectedRequest)).thenThrow(SdkClientException.create("error"));

        assertThrows(SdkClientException.class, () -> awsSnsClient.publish(MESSAGE));
    }
}
