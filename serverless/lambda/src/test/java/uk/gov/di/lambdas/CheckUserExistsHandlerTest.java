package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.CheckUserExistsResponse;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.SessionService;
import uk.gov.di.services.ValidationService;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;

class CheckUserExistsHandlerTest {

    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private CheckUserExistsHandler handler;
    private String sessionId;
    private ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    public void setup() {
        handler =
                new CheckUserExistsHandler(
                        validationService, authenticationService, sessionService);
        sessionId = UUID.randomUUID().toString();
    }

    @Test
    public void shouldReturn200IfUserExists() throws JsonProcessingException {
        usingValidSession();
        when(authenticationService.userExists(eq("joe.bloggs@digital.cabinet-office.gov.uk")))
                .thenReturn(true);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");
        event.setHeaders(Map.of("Session-Id", sessionId));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(200, result.getStatusCode());

        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
        assertEquals(
                "joe.bloggs@digital.cabinet-office.gov.uk", checkUserExistsResponse.getEmail());
        assertTrue(checkUserExistsResponse.doesUserExist());
    }

    @Test
    public void shouldReturn200IfUserDoesNotExist() throws JsonProcessingException {
        usingValidSession();
        when(authenticationService.userExists(eq("joe.bloggs@digital.cabinet-office.gov.uk")))
                .thenReturn(false);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");
        event.setHeaders(Map.of("Session-Id", sessionId));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(200, result.getStatusCode());

        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
        assertEquals(
                "joe.bloggs@digital.cabinet-office.gov.uk", checkUserExistsResponse.getEmail());
        assertFalse(checkUserExistsResponse.doesUserExist());
    }

    @Test
    public void shouldReturn400IfRequestIsMissingEmail() throws JsonProcessingException {
        usingValidSession();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ }");
        event.setHeaders(Map.of("Session-Id", sessionId));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());

        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1001);
        assertThat(result, hasBody(expectedResponse));
    }

    @Test
    public void shouldReturn400IfRequestIsMissingSessionId() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());

        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1000);
        assertThat(result, hasBody(expectedResponse));
    }

    @Test
    public void shouldReturn400IfEmailAddressIsInvalid() throws JsonProcessingException {
        usingValidSession();
        when(validationService.validateEmailAddress(eq("joe.bloggs")))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1004));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs\" }");
        event.setHeaders(Map.of("Session-Id", sessionId));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1004);

        assertThat(result, hasBody(expectedResponse));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(new Session("a-session-id")));
    }
}
