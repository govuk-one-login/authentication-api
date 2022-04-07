package uk.gov.di.authentication.oidc.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.authentication.oidc.entity.BackChannelLogoutMessage;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.AwsSqsClient;

import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class BackChannelLogoutServiceTest {

    private final AwsSqsClient sqs = mock(AwsSqsClient.class);
    private final BackChannelLogoutService service = new BackChannelLogoutService(sqs);

    @Test
    void shouldPostBackChannelLogoutMessageToSqs() throws JsonProcessingException {
        service.sendLogoutMessage(
                new ClientRegistry()
                        .setClientID("client-id")
                        .setBackChannelLogoutUri("http://localhost:8080/back-channel-logout"));

        var captor = ArgumentCaptor.forClass(String.class);

        verify(sqs).send(captor.capture());

        var message =
                ObjectMapperFactory.getInstance()
                        .readValue(captor.getValue(), BackChannelLogoutMessage.class);

        assertThat(message.getClientId(), is("client-id"));
        assertThat(message.getLogoutUri(), is("http://localhost:8080/back-channel-logout"));
    }

    @Test
    void shouldNotPostMessageToSqsWhenRequiredFieldsAreNotPresent() {
        var noLogoutUri = new ClientRegistry().setClientID("client-id");
        var noClientId = new ClientRegistry().setBackChannelLogoutUri("http://localhost:8080/");
        var neitherField = new ClientRegistry();

        Stream.of(noLogoutUri, noClientId, neitherField).forEach(service::sendLogoutMessage);

        verify(sqs, never()).send(anyString());
    }
}
