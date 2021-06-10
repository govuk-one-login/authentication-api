package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.Client;
import uk.gov.di.services.ClientService;

import java.util.List;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventStatusMatcher.hasStatus;

class ClientRegistrationHandlerTest {

    private final Context CONTEXT = mock(Context.class);
    private ClientRegistrationHandler handler;
    private final ClientService CLIENT_SERVICE = mock(ClientService.class);
    private ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    public void setup() {
        handler = new ClientRegistrationHandler(CLIENT_SERVICE);
    }

    @Test
    public void shouldReturn200IfClientRegistrationRequestIsSuccessful() throws JsonProcessingException {
        String clientName = "test-client";
        List<String> redirectUris = List.of("http://localhost:8080/redirect-uri");
        List<String> contacts = List.of("joe.bloggs@test.com");
        String clientId = UUID.randomUUID().toString();
        String clientSecret = UUID.randomUUID().toString();
        Client client = new Client(clientName, clientId, clientSecret, List.of("code"), redirectUris, contacts);
        when(CLIENT_SERVICE.addClient(clientName, redirectUris, contacts)).thenReturn(client);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"client_name\": \"test-client\", \"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"] }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertThat(result, hasStatus(200));
        Client clientResult = objectMapper.readValue(result.getBody(), Client.class);
        assertEquals(client.getClientId(), clientResult.getClientId());
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{\"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"] }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertThat(result, hasStatus(400));
        assertEquals("Request is missing parameters", result.getBody());
    }
}