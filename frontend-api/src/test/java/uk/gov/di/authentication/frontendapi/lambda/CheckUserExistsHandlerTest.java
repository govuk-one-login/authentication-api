package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class CheckUserExistsHandlerTest {

    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private CheckUserExistsHandler handler;
    private ObjectMapper objectMapper = new ObjectMapper();

    private final Session session = new Session(IdGenerator.generate()).setState(SessionState.NEW);

    @BeforeEach
    public void setup() {
        handler =
                new CheckUserExistsHandler(
                        validationService, authenticationService, sessionService);
        reset(authenticationService);
    }

    @Test
    public void shouldReturn200IfUserExists() throws JsonProcessingException {
        usingValidSession();
        when(authenticationService.userExists(eq("joe.bloggs@digital.cabinet-office.gov.uk")))
                .thenReturn(true);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
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
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(200, result.getStatusCode());

        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
        assertEquals(
                "joe.bloggs@digital.cabinet-office.gov.uk", checkUserExistsResponse.getEmail());
        assertFalse(checkUserExistsResponse.doesUserExist());
    }

    @Test
    public void shouldReturn400IfRequestIsMissingEmail() {
        usingValidSession();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ }");
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturn400IfRequestIsMissingSessionId() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
    }

    @Test
    public void shouldReturn400IfEmailAddressIsInvalid() {
        usingValidSession();
        when(validationService.validateEmailAddress(eq("joe.bloggs")))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1004));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs\" }");
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1004));
    }

    @Test
    public void shouldReturn400IfUserTransitionsFromWrongState() {
        usingValidSession();
        session.setState(SessionState.AUTHENTICATED);

        APIGatewayProxyResponseEvent result =
                handler.handleRequest(usingTestEventWithSession(session), context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1017));
    }

    @Test
    public void shouldReturn200IfUserTransitionsFromUserNotFoundAndUserDoesNotExist()
            throws JsonProcessingException {
        usingValidSession();
        session.setState(SessionState.USER_NOT_FOUND);
        when(authenticationService.userExists(eq("joe.bloggs"))).thenReturn(false);

        APIGatewayProxyResponseEvent result =
                handler.handleRequest(usingTestEventWithSession(session), context);

        assertEquals(200, result.getStatusCode());
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
        assertEquals("joe.bloggs", checkUserExistsResponse.getEmail());
        assertFalse(checkUserExistsResponse.doesUserExist());
        assertTrue(checkUserExistsResponse.getSessionState().equals(SessionState.USER_NOT_FOUND));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private APIGatewayProxyRequestEvent usingTestEventWithSession(Session testEventSession) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs\" }");
        event.setHeaders(Map.of("Session-Id", testEventSession.getSessionId()));
        return event;
    }
}
