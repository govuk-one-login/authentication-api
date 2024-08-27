package uk.gov.di.authentication.sharedtest.helper;

import com.google.gson.JsonElement;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Objects;

import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.asJson;

public class AuditAssertionsHelper {

    private static final Duration TIMEOUT = Duration.of(1, ChronoUnit.SECONDS);

    public static void assertNoTxmaAuditEventsReceived(SqsQueueExtension txmaAuditQueue) {
        await().atMost(TIMEOUT)
                .untilAsserted(
                        () -> assertThat(txmaAuditQueue.getApproximateMessageCount(), equalTo(0)));
    }

    public static void assertTxmaAuditEventsSubmittedWithMatchingNames(
            SqsQueueExtension queue, Collection<AuditableEvent> events) {
        var expectedTxmaEvents = events.stream().map(Objects::toString).toList();

        if (expectedTxmaEvents.isEmpty()) {
            throw new RuntimeException(
                    "Do not call assertTxmaAuditEventsReceived() with an empty collection of event types; it won't wait to see if anything unexpected was received.  Instead, call Thread.sleep and then check the count of requests.");
        }

        await().atMost(TIMEOUT)
                .untilAsserted(
                        () ->
                                assertThat(
                                        queue.getApproximateMessageCount(),
                                        equalTo(expectedTxmaEvents.size())));

        var sentEvents = queue.getRawMessages().stream().toList();

        var namesOfSentEvents =
                sentEvents.stream()
                        .map(
                                event ->
                                        asJson(event)
                                                .getAsJsonObject()
                                                .get("event_name")
                                                .getAsString())
                        .toList();

        // Check all expected events have been sent
        // Check no unexpected events were sent
        assertTrue(
                expectedTxmaEvents.containsAll(namesOfSentEvents)
                        && namesOfSentEvents.containsAll(expectedTxmaEvents));
    }

    public static void assertTxmaAuditEventsReceived(
            SqsQueueExtension queue, Collection<AuditableEvent> events) {

        var expectedTxmaEvents = events.stream().map(Objects::toString).toList();

        if (expectedTxmaEvents.isEmpty()) {
            throw new RuntimeException(
                    "Do not call assertTxmaAuditEventsReceived() with an empty collection of event types; it won't wait to see if anything unexpected was received.  Instead, call Thread.sleep and then check the count of requests.");
        }

        await().atMost(TIMEOUT)
                .untilAsserted(
                        () ->
                                assertThat(
                                        queue.getApproximateMessageCount(),
                                        equalTo(expectedTxmaEvents.size())));

        var sentEvents = queue.getRawMessages().stream().toList();

        var namesOfSentEvents =
                sentEvents.stream()
                        .map(
                                event ->
                                        asJson(event)
                                                .getAsJsonObject()
                                                .get("event_name")
                                                .getAsString())
                        .toList();

        // Check all expected events have been sent
        // Check no unexpected events were sent
        assertTrue(
                expectedTxmaEvents.containsAll(namesOfSentEvents)
                        && namesOfSentEvents.containsAll(expectedTxmaEvents));

        // Check all sent events applied business rules, i.e. include a device_information section.
        sentEvents.forEach(
                sentEvent -> {
                    var event = asJson(sentEvent);
                    assertValidAuditEventsHaveDeviceInformationInRestrictedSection(event);
                });
    }

    private static void assertValidAuditEventsHaveDeviceInformationInRestrictedSection(
            JsonElement event) {
        assertNotNull(event.getAsJsonObject().get("restricted"));
        assertNotNull(
                event.getAsJsonObject()
                        .get("restricted")
                        .getAsJsonObject()
                        .get("device_information"));
    }
}
