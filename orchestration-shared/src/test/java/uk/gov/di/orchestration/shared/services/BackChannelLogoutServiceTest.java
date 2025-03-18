package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import uk.gov.di.orchestration.shared.entity.BackChannelLogoutMessage;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.UserProfile;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper.calculatePairwiseIdentifier;

class BackChannelLogoutServiceTest {

    private final AwsSqsClient sqs = Mockito.mock(AwsSqsClient.class);
    private final AuthenticationService authenticationService =
            Mockito.mock(AuthenticationService.class);
    private final BackChannelLogoutService service = new BackChannelLogoutService(sqs);
    private static final String RP_SECTOR_HOST = "example.sign-in.service.gov.uk";
    private static final String SUBJECT_ID = "subject";
    private static String rpPairwiseId;

    @Test
    void shouldPostBackChannelLogoutMessageToSqsForPairwiseClients() {
        var user = new UserProfile().withPublicSubjectID("public").withSubjectID(SUBJECT_ID);

        Mockito.when(authenticationService.getUserProfileByEmailMaybe("test@test.com"))
                .thenReturn(Optional.of(user));
        Mockito.when(authenticationService.getOrGenerateSalt(user))
                .thenReturn("salt".getBytes(StandardCharsets.UTF_8));

        rpPairwiseId =
                calculatePairwiseIdentifier(
                        SUBJECT_ID, RP_SECTOR_HOST, authenticationService.getOrGenerateSalt(user));

        service.sendLogoutMessage(
                new ClientRegistry()
                        .withClientID("client-id")
                        .withSubjectType("pairwise")
                        .withSectorIdentifierUri("https://example.sign-in.service.gov.uk")
                        .withBackChannelLogoutUri("http://localhost:8080/back-channel-logout"),
                rpPairwiseId);

        var captor = ArgumentCaptor.forClass(BackChannelLogoutMessage.class);

        Mockito.verify(sqs).sendAsync(captor.capture());

        var message = captor.getValue();

        assertThat(message.getClientId(), is("client-id"));
        assertThat(message.getLogoutUri(), is("http://localhost:8080/back-channel-logout"));
        assertThat(
                message.getSubjectId(),
                is("urn:fdc:gov.uk:2022:tGOB5t5fRAX_Fio6qRIj8KPDL7vOg5gCqI4l5nDZCDs"));
    }

    @Test
    void shouldNotPostMessageToSqsWhenRequiredFieldsAreNotPresent() {
        var noLogoutUri = new ClientRegistry().withClientID("client-id");
        var noClientId = new ClientRegistry().withBackChannelLogoutUri("http://localhost:8080/");
        var neitherField = new ClientRegistry();

        Stream.of(noLogoutUri, noClientId, neitherField)
                .forEach(
                        clientRegistry ->
                                service.sendLogoutMessage(clientRegistry, "dummy-rpPairwiseId"));

        Mockito.verify(sqs, Mockito.never()).send(ArgumentMatchers.anyString());
    }

    @Test
    void shouldNotPostMessageToSqsIfUserProfileDoesNotExist() {
        Mockito.when(authenticationService.getUserProfileByEmailMaybe("test@test.com"))
                .thenReturn(Optional.empty());

        service.sendLogoutMessage(
                new ClientRegistry()
                        .withClientID("client-id")
                        .withBackChannelLogoutUri("http://localhost:8080/back-channel-logout"),
                "dummy-rpPairwiseId");

        Mockito.verify(sqs, Mockito.never()).send(ArgumentMatchers.anyString());
    }
}
