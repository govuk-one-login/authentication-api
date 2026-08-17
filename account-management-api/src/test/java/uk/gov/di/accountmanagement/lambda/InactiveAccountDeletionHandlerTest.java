package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class InactiveAccountDeletionHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private InactiveAccountDeletionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new InactiveAccountDeletionHandler(configurationService);
    }

    @Test
    void shouldReportValidMessageAsFailureUntilDeletionIsImplemented() {
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"urn:fdc:gov.uk:2022:abc123\"}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        assertEquals("msg-1", response.getBatchItemFailures().get(0).getItemIdentifier());
    }

    @Test
    void shouldReportMalformedJsonAsFailure() {
        var event = createSQSEventWithBody("not valid json");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        assertEquals("msg-1", response.getBatchItemFailures().get(0).getItemIdentifier());
    }

    @Test
    void shouldReportMissingPublicSubjectIdAsFailure() {
        var event = createSQSEventWithBody("{\"publicSubjectId\": \"\"}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        assertEquals("msg-1", response.getBatchItemFailures().get(0).getItemIdentifier());
    }

    @Test
    void shouldReportNullPublicSubjectIdAsFailure() {
        var event = createSQSEventWithBody("{}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        assertEquals("msg-1", response.getBatchItemFailures().get(0).getItemIdentifier());
    }

    @Test
    void shouldHandleNullEvent() {
        SQSBatchResponse response = handler.handleRequest(null, context);

        assertThat(response.getBatchItemFailures(), is(empty()));
    }

    @Test
    void shouldProcessMultipleMessagesAndReportAllAsFailuresUntilDeletionIsImplemented() {
        var validMessage = createSQSMessage("msg-good", "{\"publicSubjectId\": \"sub-1\"}");
        var invalidMessage = createSQSMessage("msg-bad", "invalid json");
        var anotherValid = createSQSMessage("msg-good-2", "{\"publicSubjectId\": \"sub-2\"}");

        var event = new SQSEvent();
        event.setRecords(List.of(validMessage, invalidMessage, anotherValid));

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(3));
    }

    private SQSEvent createSQSEventWithBody(String body) {
        var message = createSQSMessage("msg-1", body);
        var event = new SQSEvent();
        event.setRecords(List.of(message));
        return event;
    }

    private SQSMessage createSQSMessage(String messageId, String body) {
        var message = new SQSMessage();
        message.setMessageId(messageId);
        message.setBody(body);
        return message;
    }
}
