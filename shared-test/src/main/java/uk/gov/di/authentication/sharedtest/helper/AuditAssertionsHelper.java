package uk.gov.di.authentication.sharedtest.helper;

import com.google.gson.JsonElement;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
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
        assertTxmaAuditEventsSubmittedWithMatchingNames(queue, events, false);
    }

    public static void assertTxmaAuditEventsSubmittedWithMatchingNames(
            SqsQueueExtension queue, Collection<AuditableEvent> events, boolean ordered) {
        var expectedTxmaEvents = events.stream().map(Objects::toString).toList();

        if (expectedTxmaEvents.isEmpty()) {
            throw new IllegalArgumentException(
                    "Do not call assertTxmaAuditEventsReceived() with an empty collection of event types; it won't wait to see if anything unexpected was received.  Instead, call Thread.sleep and then check the count of requests.");
        }

        if (!expectedTxmaEvents.stream().allMatch(item -> item.startsWith("AUTH_"))) {
            throw new IllegalArgumentException(
                    "assertTxmaAuditEventsReceived() should have authentication audit events starting with AUTH_");
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
        if (ordered) {
            assertTrue(expectedTxmaEvents.equals(namesOfSentEvents));
        } else {
            assertTrue(
                    expectedTxmaEvents.containsAll(namesOfSentEvents)
                            && namesOfSentEvents.containsAll(expectedTxmaEvents));
        }
    }

    public static List<String> assertTxmaAuditEventsReceived(
            SqsQueueExtension queue, Collection<AuditableEvent> events) {
        return assertTxmaAuditEventsReceived(queue, events, true);
    }

    public static List<String> assertTxmaAuditEventsReceived(
            SqsQueueExtension queue,
            Collection<AuditableEvent> events,
            boolean validateDeviceInformation) {

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
        var missingEvents =
                expectedTxmaEvents.stream()
                        .filter(event -> !namesOfSentEvents.contains(event))
                        .toList();
        assertTrue(
                missingEvents.isEmpty(),
                String.format(
                        "Missing expected audit events: %s. Expected: %s, Actual: %s",
                        missingEvents, expectedTxmaEvents, namesOfSentEvents));

        // Check no unexpected events were sent
        var unexpectedEvents =
                namesOfSentEvents.stream()
                        .filter(event -> !expectedTxmaEvents.contains(event))
                        .toList();
        assertTrue(
                unexpectedEvents.isEmpty(),
                String.format(
                        "Received unexpected audit events: %s. Expected: %s, Actual: %s",
                        unexpectedEvents, expectedTxmaEvents, namesOfSentEvents));

        // Check all sent events applied business rules, i.e. include a device_information section.
        if (validateDeviceInformation) {
            sentEvents.forEach(
                    sentEvent -> {
                        var event = asJson(sentEvent);
                        assertValidAuditEventsHaveDeviceInformationInRestrictedSection(event);
                    });
        }

        return sentEvents;
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

    public static void containsMetadataPair(
            AuditContext capturedObject, String field, String value) {
        capturedObject
                .getMetadataItemByKey(field)
                .ifPresentOrElse(
                        actualMetadataPairForMfaMethod ->
                                assertEquals(
                                        AuditService.MetadataPair.pair(field, value),
                                        actualMetadataPairForMfaMethod),
                        () -> fail("Missing metadata key: " + field));
    }

    public static void assertAuditEventExpectations(
            SqsQueueExtension queue, List<AuditEventExpectation> expectedEvents) {
        List<AuditableEvent> events =
                expectedEvents.stream().map(AuditEventExpectation::getEvent).toList();

        List<String> receivedEvents = assertTxmaAuditEventsReceived(queue, events);

        for (AuditEventExpectation expectation : expectedEvents) {
            expectation.assertPublished(receivedEvents);
        }

        assertNoTxmaAuditEventsReceived(queue);
    }
}
