package uk.gov.di.authentication.oidc.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.authentication.oidc.entity.BackChannelLogoutMessage;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;

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

    @Test
    void shouldPostBackChannelLogoutMessageToSqsForPairwiseClients()
            throws JsonProcessingException {
        var user = new UserProfile().setPublicSubjectID("public").setSubjectID("subject");

        when(authenticationService.getUserProfileByEmailMaybe("test@test.com"))
                .thenReturn(Optional.of(user));
        when(authenticationService.getOrGenerateSalt(user)).thenReturn("salt".getBytes());

        service.sendLogoutMessage(
                new ClientRegistry()
                        .setClientID("client-id")
                        .setSubjectType("pairwise")
                        .setSectorIdentifierUri("https://example.sign-in.service.gov.uk")
                        .setBackChannelLogoutUri("http://localhost:8080/back-channel-logout"),
                "test@test.com");

        var captor = ArgumentCaptor.forClass(String.class);

        verify(sqs).send(captor.capture());

        var message =
                ObjectMapperFactory.getInstance()
                        .readValue(captor.getValue(), BackChannelLogoutMessage.class);

        assertThat(message.getClientId(), is("client-id"));
        assertThat(message.getLogoutUri(), is("http://localhost:8080/back-channel-logout"));
        assertThat(
                message.getSubjectId(),
                is("1b8920099adc11e966d68335276d1db274e8c79588b2b608f9182ecc3908ee07"));
    }

    @Test
    void shouldNotPostMessageToSqsWhenRequiredFieldsAreNotPresent() {
        var noLogoutUri = new ClientRegistry().setClientID("client-id");
        var noClientId = new ClientRegistry().setBackChannelLogoutUri("http://localhost:8080/");
        var neitherField = new ClientRegistry();

        Stream.of(noLogoutUri, noClientId, neitherField)
                .forEach(clientRegistry -> service.sendLogoutMessage(clientRegistry, null));

        verify(sqs, never()).send(anyString());
    }

    @Test
    void shouldNotPostMessageToSqsIfUserProfileDoesNotExist() {
        when(authenticationService.getUserProfileByEmailMaybe("test@test.com"))
                .thenReturn(Optional.empty());

        service.sendLogoutMessage(
                new ClientRegistry()
                        .setClientID("client-id")
                        .setBackChannelLogoutUri("http://localhost:8080/back-channel-logout"),
                "test@test.com");

        verify(sqs, never()).send(anyString());
    }
}
