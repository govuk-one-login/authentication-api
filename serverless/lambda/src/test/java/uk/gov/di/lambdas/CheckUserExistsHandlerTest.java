package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.services.UserService;
import uk.gov.di.services.ValidationService;
import uk.gov.di.validation.EmailValidation;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CheckUserExistsHandlerTest {

    private final Context CONTEXT = mock(Context.class);
    private final UserService USER_SERVICE = mock(UserService.class);
    private final ValidationService VALIDATION_SERVICE = mock(ValidationService.class);
    private CheckUserExistsHandler handler;
    private String sessionId;

    @BeforeEach
    public void setup() {
        handler = new CheckUserExistsHandler(VALIDATION_SERVICE, USER_SERVICE);
        sessionId = UUID.randomUUID().toString();
    }

    @Test
    public void shouldReturn200IfUserExists() {
        when(USER_SERVICE.userExists(eq("joe.bloggs@digital.cabinet-office.gov.uk"))).thenReturn(true);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");
        event.setHeaders(Map.of("session-id", sessionId));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(200, result.getStatusCode());
        assertEquals("User has an account", result.getBody());
    }

    @Test
    public void shouldReturn404IfUserDoesNotExist() {
        when(USER_SERVICE.userExists(eq("joe.bloggs@digital.cabinet-office.gov.uk"))).thenReturn(false);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");
        event.setHeaders(Map.of("session-id", sessionId));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(404, result.getStatusCode());
        assertEquals("User not found", result.getBody());
    }

    @Test
    public void shouldReturn400IfRequestIsMissingEmail() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ }");
        event.setHeaders(Map.of("session-id", sessionId));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(400, result.getStatusCode());
        assertEquals("Request is missing parameters", result.getBody());
    }

    @Test
    public void shouldReturn400IfRequestIsMissingSessionId() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(400, result.getStatusCode());
        assertEquals("session-id is missing", result.getBody());
    }

    @Test
    public void shouldReturn400IfEmailAddressIsInvalid() {
        when(VALIDATION_SERVICE.validateEmailAddress(eq("joe.bloggs"))).thenReturn(Set.of(EmailValidation.INCORRECT_FORMAT));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs\" }");
        event.setHeaders(Map.of("session-id", sessionId));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(400, result.getStatusCode());
        assertTrue(result.getBody().contains(EmailValidation.INCORRECT_FORMAT.toString()));
    }
}