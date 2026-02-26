package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import uk.gov.di.orchestration.shared.entity.BackChannelLogoutMessage;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.helpers.SaltHelper;

import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper.calculatePairwiseIdentifier;

// QualityGateUnitTest
class BackChannelLogoutServiceTest {

    private final AwsSqsClient sqs = mock(AwsSqsClient.class);
    private final BackChannelLogoutService service = new BackChannelLogoutService(sqs);
    private static final String RP_SECTOR_HOST = "example.sign-in.service.gov.uk";
    private static final String SUBJECT_ID = "subject";

    // QualityGateRegressionTest
    @Test
    void shouldPostBackChannelLogoutMessageToSqsForPairwiseClients() {
        var rpPairwiseId =
                calculatePairwiseIdentifier(
                        SUBJECT_ID, RP_SECTOR_HOST, SaltHelper.generateNewSalt());

        service.sendLogoutMessage(
                new ClientRegistry()
                        .withClientID("client-id")
                        .withSubjectType("pairwise")
                        .withSectorIdentifierUri("https://example.sign-in.service.gov.uk")
                        .withBackChannelLogoutUri("http://localhost:8080/back-channel-logout"),
                rpPairwiseId);

        var captor = ArgumentCaptor.forClass(BackChannelLogoutMessage.class);

        verify(sqs).sendAsync(captor.capture());

        var message = captor.getValue();

        assertThat(message.getClientId(), is("client-id"));
        assertThat(message.getLogoutUri(), is("http://localhost:8080/back-channel-logout"));
        assertThat(message.getSubjectId(), is(rpPairwiseId));
    }

    // QualityGateRegressionTest
    @Test
    void shouldNotPostMessageToSqsWhenRequiredFieldsAreNotPresent() {
        var noLogoutUri = new ClientRegistry().withClientID("client-id");
        var noClientId = new ClientRegistry().withBackChannelLogoutUri("http://localhost:8080/");
        var neitherField = new ClientRegistry();

        Stream.of(noLogoutUri, noClientId, neitherField)
                .forEach(
                        clientRegistry ->
                                service.sendLogoutMessage(clientRegistry, "dummy-rpPairwiseId"));

        verify(sqs, never()).send(ArgumentMatchers.anyString());
    }
}
