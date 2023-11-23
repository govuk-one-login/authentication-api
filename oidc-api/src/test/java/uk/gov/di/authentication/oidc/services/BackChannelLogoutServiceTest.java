package uk.gov.di.authentication.oidc.services;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.authentication.oidc.entity.BackChannelLogoutMessage;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.services.AuthenticationService;
import uk.gov.di.orchestration.shared.services.AwsSqsClient;

import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BackChannelLogoutServiceTest {

    private final AwsSqsClient sqs = mock(AwsSqsClient.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final BackChannelLogoutService service =
            new BackChannelLogoutService(sqs, authenticationService);
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";

    @Test
    void shouldPostBackChannelLogoutMessageToSqsForPairwiseClients() {
        var user = new UserProfile().withPublicSubjectID("public").withSubjectID("subject");

        when(authenticationService.getUserProfileByEmailMaybe("test@test.com"))
                .thenReturn(Optional.of(user));
        when(authenticationService.getOrGenerateSalt(user)).thenReturn("salt".getBytes());

        service.sendLogoutMessage(
                new ClientRegistry()
                        .withClientID("client-id")
                        .withSubjectType("pairwise")
                        .withSectorIdentifierUri("https://example.sign-in.service.gov.uk")
                        .withBackChannelLogoutUri("http://localhost:8080/back-channel-logout"),
                "test@test.com",
                INTERNAL_SECTOR_URI);

        var captor = ArgumentCaptor.forClass(BackChannelLogoutMessage.class);

        verify(sqs).sendAsync(captor.capture());

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
                                service.sendLogoutMessage(
                                        clientRegistry, null, INTERNAL_SECTOR_URI));

        verify(sqs, never()).send(anyString());
    }

    @Test
    void shouldNotPostMessageToSqsIfUserProfileDoesNotExist() {
        when(authenticationService.getUserProfileByEmailMaybe("test@test.com"))
                .thenReturn(Optional.empty());

        service.sendLogoutMessage(
                new ClientRegistry()
                        .withClientID("client-id")
                        .withBackChannelLogoutUri("http://localhost:8080/back-channel-logout"),
                "test@test.com",
                INTERNAL_SECTOR_URI);

        verify(sqs, never()).send(anyString());
    }
}
