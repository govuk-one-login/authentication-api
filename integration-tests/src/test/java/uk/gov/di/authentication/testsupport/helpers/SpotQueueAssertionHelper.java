package uk.gov.di.authentication.testsupport.helpers;

import uk.gov.di.authentication.ipv.entity.SPOTRequest;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;

import java.util.Collection;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.authentication.testsupport.matchers.SpotRequestMatcher.hasCredential;
import static uk.gov.di.authentication.testsupport.matchers.SpotRequestMatcher.hasPairwiseIdentifier;

public class SpotQueueAssertionHelper {

    private static final int SPOT_TIMEOUT = 1;

    public static void assertSpotRequestReceived(
            SqsQueueExtension spotQueue, Collection<SPOTRequest> expectedRequests) {
        if (expectedRequests.isEmpty()) {
            throw new RuntimeException(
                    "Do not call assertSpotRequestReceived() with an empty collection of SPOT requests; it won't wait to see if anything unexpected was received.  Instead, use assertSpotRequestReceived().");
        }

        await().atMost(SPOT_TIMEOUT, SECONDS)
                .untilAsserted(
                        () ->
                                assertThat(
                                        spotQueue.getApproximateMessageCount(),
                                        equalTo(expectedRequests.size())));

        var actualRequests = spotQueue.getMessages(SPOTRequest.class);
        expectedRequests.forEach(
                spotRequest ->
                        assertThat(
                                actualRequests,
                                hasItem(
                                        allOf(
                                                hasPairwiseIdentifier(
                                                        spotRequest.getPairwiseIdentifier()),
                                                hasCredential(
                                                        spotRequest.getSerializedCredential())))));

        assertThat(
                "Expected no more notifications to come through",
                spotQueue.getMessages(Object.class),
                hasSize(0));
    }
}
