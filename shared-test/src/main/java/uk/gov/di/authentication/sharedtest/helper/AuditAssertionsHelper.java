package uk.gov.di.authentication.sharedtest.helper;

import com.google.gson.JsonElement;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.authentication.sharedtest.matchers.JsonMatcher;

import java.util.Collection;
import java.util.Objects;
import java.util.stream.Collectors;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;

public class AuditAssertionsHelper {

    private static final int SNS_TIMEOUT = 1;
    public static final int SNS_TIMEOUT_MILLIS = SNS_TIMEOUT * 1000;

    public static void assertNoTxmaAuditEventsReceived(SqsQueueExtension txmaAuditQueue) {
        try {
            Thread.sleep(SNS_TIMEOUT_MILLIS);
        } catch (InterruptedException ex) {
            throw new RuntimeException(ex);
        }
        assertThat(txmaAuditQueue.getApproximateMessageCount(), equalTo(0));
    }

    public static void assertTxmaAuditEventsReceived(
            SqsQueueExtension queue, Collection<AuditableEvent> events) {

        var txmaEvents =
                events.stream()
                        .map(Objects::toString)
                        .map("AUTH_"::concat)
                        .collect(Collectors.toList());

        if (txmaEvents.isEmpty()) {
            throw new RuntimeException(
                    "Do not call assertTxmaAuditEventsReceived() with an empty collection of event types; it won't wait to see if anything unexpected was received.  Instead, call Thread.sleep and then check the count of requests.");
        }

        await().atMost(SNS_TIMEOUT, SECONDS)
                .untilAsserted(
                        () ->
                                assertThat(
                                        queue.getApproximateMessageCount(),
                                        equalTo(txmaEvents.size())));

        var receivedEvents =
                queue.getRawMessages().stream()
                        .map(JsonMatcher::asJson)
                        .map(JsonElement::getAsJsonObject)
                        .map(json -> json.get("event_name"))
                        .map(JsonElement::getAsString)
                        .collect(Collectors.toSet());

        txmaEvents.stream()
                .map(Object::toString)
                .forEach(expected -> assertThat(receivedEvents, hasItem(expected)));
    }
}
