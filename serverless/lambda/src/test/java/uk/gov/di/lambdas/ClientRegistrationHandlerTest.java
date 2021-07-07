package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.Client;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.services.ClientService;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ClientRegistrationHandlerTest {

    private final Context context = mock(Context.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private ClientRegistrationHandler handler;

    @BeforeEach
    public void setup() {
        handler = new ClientRegistrationHandler(clientService);
    }

    @Test
    public void shouldReturn200IfClientRegistrationRequestIsSuccessful()
            throws JsonProcessingException {
        String clientName = "test-client";
        List<String> redirectUris = List.of("http://localhost:8080/redirect-uri");
        List<String> contacts = List.of("joe.bloggs@test.com");
        String clientId = UUID.randomUUID().toString();
        Client client = new Client(clientName, clientId, redirectUris, contacts);
        ClientRegistry clientRegistry =
                new ClientRegistry()
                        .setClientID(clientId)
                        .setClientName(clientName)
                        .setPublicKey("")
                        .setClientFriendlyName("")
                        .setScopes(Collections.singletonList(""))
                        .setRedirectUrls(Collections.singletonList(""));
        when(clientService.addClient(clientName, redirectUris, contacts))
                .thenReturn(clientRegistry);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                "{ \"client_name\": \"test-client\", \"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"] }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        Client clientResult = objectMapper.readValue(result.getBody(), Client.class);
        assertEquals(client.getClientId(), clientResult.getClientId());
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                "{\"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"] }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1001);
        assertThat(result, hasBody(expectedResponse));
    }
}
