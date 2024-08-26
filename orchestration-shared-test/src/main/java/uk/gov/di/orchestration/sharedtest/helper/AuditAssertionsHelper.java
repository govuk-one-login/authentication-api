package uk.gov.di.orchestration.sharedtest.helper;

import com.google.gson.JsonElement;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.orchestration.sharedtest.matchers.JsonMatcher;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;

public class AuditAssertionsHelper {

    private static final Duration TIMEOUT = Duration.of(1, ChronoUnit.SECONDS);

    public static void assertNoTxmaAuditEventsReceived(SqsQueueExtension txmaAuditQueue) {
        await().atMost(TIMEOUT)
                .untilAsserted(
                        () -> assertThat(txmaAuditQueue.getApproximateMessageCount(), equalTo(0)));
    }

    public static void assertTxmaAuditEventsReceived(
            SqsQueueExtension queue, Collection<AuditableEvent> events) {

        var txmaEvents = events.stream().map(Objects::toString).toList();

        if (txmaEvents.isEmpty()) {
            throw new RuntimeException(
                    "Do not call assertTxmaAuditEventsReceived() with an empty collection of event types; it won't wait to see if anything unexpected was received.  Instead, call Thread.sleep and then check the count of requests.");
        }

        await().atMost(TIMEOUT)
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
