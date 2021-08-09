package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ClientRegistrationResponse;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.UpdateClientConfigRequest;
import uk.gov.di.services.ClientService;

import java.util.List;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateClientConfigHandlerTest {

    private static final String CLIENT_ID = "client-id-1";
    private static final String CLIENT_NAME = "client-name-one";
    private static final List<String> SCOPES = singletonList("openid");
    private final Context context = mock(Context.class);
    private final ClientService clientService = mock(ClientService.class);
    private UpdateClientConfigHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new UpdateClientConfigHandler(clientService);
    }

    @Test
    public void shouldReturn200ForAValidRequest() throws JsonProcessingException {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(true);
        when(clientService.updateClient(any(UpdateClientConfigRequest.class)))
                .thenReturn(createClientRegistry());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{ \"client_id\": \"%s\", \"client_name\": \"%s\"}",
                        CLIENT_ID, CLIENT_NAME));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        ClientRegistrationResponse clientRegistrationResponse =
                new ObjectMapper().readValue(result.getBody(), ClientRegistrationResponse.class);
        assertThat(clientRegistrationResponse.getClientId(), equalTo(CLIENT_ID));
        assertThat(clientRegistrationResponse.getClientName(), equalTo(CLIENT_NAME));
        assertThat(clientRegistrationResponse.getSubjectType(), equalTo("Public"));
        assertThat(clientRegistrationResponse.getTokenAuthMethod(), equalTo("private_key_jwt"));
        assertThat(clientRegistrationResponse.getScopes(), equalTo(SCOPES));
    }

    @Test
    public void shouldReturn400WhenRequestIsMissingClientID() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{\"client_name\": \"%s\"}", CLIENT_NAME));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
    }

    @Test
    public void shouldReturn401WhenClientIdIsInvalid() {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(false);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{ \"client_id\": \"%s\", \"client_name\": \"%s\"}",
                        CLIENT_ID, CLIENT_NAME));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(401));
    }

    private ClientRegistry createClientRegistry() {
        ClientRegistry clientRegistry = new ClientRegistry();
        clientRegistry.setClientName(CLIENT_NAME);
        clientRegistry.setClientID(CLIENT_ID);
        clientRegistry.setPublicKey("public-key");
        clientRegistry.setScopes(SCOPES);
        clientRegistry.setRedirectUrls(singletonList("http://localhost/redirect"));
        clientRegistry.setContacts(singletonList("contant-name"));
        clientRegistry.setPostLogoutRedirectUrls(singletonList("localhost/logout"));
        return clientRegistry;
    }
}
