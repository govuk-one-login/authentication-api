package uk.gov.di.orchestration.sharedtest.helper;

import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.util.List;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static uk.gov.di.orchestration.sharedtest.exceptions.Unchecked.unchecked;

public class SqsTestHelper {
    private SqsTestHelper() {}

    public static <T> SQSEvent sqsEventWithPayload(T payload) {
        var messages = sqsMessageWithPayload(payload, "messageId");
        var event = new SQSEvent();
        event.setRecords(messages.map(List::of).orElse(emptyList()));

        return event;
    }

    public static <T> Optional<SQSEvent.SQSMessage> sqsMessageWithPayload(
            T payload, String messageId) {
        return Optional.ofNullable(payload)
                .map(unchecked(SerializationService.getInstance()::writeValueAsString))
                .map(
                        body -> {
                            var message = new SQSEvent.SQSMessage();
                            message.setBody(body);
                            message.setMessageId(messageId);

                            return message;
                        });
    }
}
