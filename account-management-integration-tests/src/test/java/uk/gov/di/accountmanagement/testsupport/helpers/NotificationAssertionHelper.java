package uk.gov.di.accountmanagement.testsupport.helpers;

import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;

import java.util.Collection;
import java.util.List;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.accountmanagement.testsupport.matchers.NotifyRequestMatcher.hasDestination;
import static uk.gov.di.accountmanagement.testsupport.matchers.NotifyRequestMatcher.hasNotificationType;

public class NotificationAssertionHelper {

    private static final int NOTIFICATIONS_TIMEOUT = 1;
    public static final int NOTIFICATIONS_TIMEOUT_MILLIS = NOTIFICATIONS_TIMEOUT * 1000;

    public static void assertNoNotificationsReceived(SqsQueueExtension notificationsQueue) {
        try {
            Thread.sleep(NOTIFICATIONS_TIMEOUT_MILLIS);
        } catch (InterruptedException ex) {
            throw new RuntimeException(ex);
        }

        assertThat(notificationsQueue.getMessages(NotifyRequest.class), hasSize(0));
    }

    public static void assertNotificationsReceived(
            SqsQueueExtension notificationsQueue, Collection<NotifyRequest> expectedRequests) {
        if (expectedRequests.isEmpty()) {
            throw new RuntimeException(
                    "Do not call assertNotificationsReceived() with an empty collection of notify requests; it won't wait to see if anything unexpected was received.  Instead, use assertNoNotificationsReceived().");
        }

        await().atMost(NOTIFICATIONS_TIMEOUT, SECONDS)
                .untilAsserted(
                        () ->
                                assertThat(
                                        notificationsQueue.getApproximateMessageCount(),
                                        equalTo(expectedRequests.size())));

        List<NotifyRequest> actualRequests = notificationsQueue.getMessages(NotifyRequest.class);
        expectedRequests.forEach(
                notifyRequest ->
                        assertThat(
                                actualRequests,
                                hasItem(
                                        allOf(
                                                hasDestination(notifyRequest.getDestination()),
                                                hasNotificationType(
                                                        notifyRequest.getNotificationType())))));

        assertThat(
                "Expected no more notifications to come through",
                notificationsQueue.getMessages(Object.class),
                hasSize(0));
    }
}
