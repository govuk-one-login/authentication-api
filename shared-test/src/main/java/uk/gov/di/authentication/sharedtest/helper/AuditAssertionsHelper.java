package uk.gov.di.authentication.sharedtest.helper;

import com.google.gson.JsonElement;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.sharedtest.extensions.AuditSnsTopicExtension;
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
import static uk.gov.di.authentication.sharedtest.matchers.AuditEventMatcher.hasEventType;

public class AuditAssertionsHelper {

    private static final int SNS_TIMEOUT = 1;
    public static final int SNS_TIMEOUT_MILLIS = SNS_TIMEOUT * 1000;

    public static void assertNoAuditEventsReceivedByEitherService(
            AuditSnsTopicExtension auditTopic, SqsQueueExtension txmaAuditQueue) {
        assertNoAuditEventsReceived(auditTopic);
        assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    public static void assertNoAuditEventsReceived(AuditSnsTopicExtension auditTopic) {
        try {
            Thread.sleep(SNS_TIMEOUT_MILLIS);
        } catch (InterruptedException ex) {
            throw new RuntimeException(ex);
        }

        assertThat(auditTopic.getCountOfRequests(), equalTo(0));
    }

    public static void assertNoTxmaAuditEventsReceived(SqsQueueExtension txmaAuditQueue) {
        try {
            Thread.sleep(SNS_TIMEOUT_MILLIS);
        } catch (InterruptedException ex) {
            throw new RuntimeException(ex);
        }
        assertThat(txmaAuditQueue.getApproximateMessageCount(), equalTo(0));
    }

    public static void assertEventTypesReceivedByBothServices(
            AuditSnsTopicExtension auditTopic,
            SqsQueueExtension txmaAuditQueue,
            Collection<AuditableEvent> eventTypes) {

        assertEventTypesReceived(auditTopic, eventTypes);

        var txmaEvents =
                eventTypes.stream()
                        .map(Objects::toString)
                        .map("AUTH_"::concat)
                        .collect(Collectors.toList());

        assertTxmaAuditEventsReceived(txmaAuditQueue, txmaEvents);
    }

    public static void assertEventTypesReceived(
            AuditSnsTopicExtension auditTopic, Collection<AuditableEvent> eventTypes) {
        if (eventTypes.isEmpty()) {
            throw new RuntimeException(
                    "Do not call assertEventTypesReceived() with an empty collection of event types; it won't wait to see if anything unexpected was received.  Instead, call Thread.sleep and then check the count of requests.");
        }

        await().atMost(SNS_TIMEOUT, SECONDS)
                .untilAsserted(
                        () ->
                                assertThat(
                                        auditTopic.getCountOfRequests(),
                                        equalTo(eventTypes.size())));

        eventTypes.forEach(
                eventType ->
                        await().atMost(SNS_TIMEOUT, SECONDS)
                                .untilAsserted(
                                        () ->
                                                assertThat(
                                                        auditTopic.getAuditEvents(),
                                                        hasItem(hasEventType(eventType)))));

        // Check that no more events came through while we were looking for the ones we expected.
        assertThat(auditTopic.getCountOfRequests(), equalTo(eventTypes.size()));
    }

    public static void assertTxmaAuditEventsReceived(
            SqsQueueExtension tmxaAuditQueue, Collection<String> eventTypes) {
        if (eventTypes.isEmpty()) {
            throw new RuntimeException(
                    "Do not call assertTxmaAuditEventsReceived() with an empty collection of event types; it won't wait to see if anything unexpected was received.  Instead, call Thread.sleep and then check the count of requests.");
        }

        await().atMost(SNS_TIMEOUT, SECONDS)
                .untilAsserted(
                        () ->
                                assertThat(
                                        tmxaAuditQueue.getApproximateMessageCount(),
                                        equalTo(eventTypes.size())));

        var receivedEvents =
                tmxaAuditQueue.getRawMessages().stream()
                        .peek(System.out::println)
                        .map(JsonMatcher::asJson)
                        .map(JsonElement::getAsJsonObject)
                        .map(json -> json.get("event_name"))
                        .map(JsonElement::getAsString)
                        .collect(Collectors.toSet());

        eventTypes.stream()
                .map(Object::toString)
                .forEach(expected -> assertThat(receivedEvents, hasItem(expected)));
    }
}
