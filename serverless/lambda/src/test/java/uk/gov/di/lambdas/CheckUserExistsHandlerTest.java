package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.services.UserService;
import uk.gov.di.services.ValidationService;
import uk.gov.di.validation.EmailValidation;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CheckUserExistsHandlerTest {

    private final Context CONTEXT = mock(Context.class);
    private final UserService USER_SERVICE = mock(UserService.class);
    private final ValidationService VALIDATION_SERVICE = mock(ValidationService.class);
    private CheckUserExistsHandler handler;

    @BeforeEach
    public void setup() {
        handler = new CheckUserExistsHandler(VALIDATION_SERVICE, USER_SERVICE);
    }

    @Test
    public void shouldReturn200IfUserExists() {
        when(USER_SERVICE.userExists(eq("joe.bloggs@digital.cabinet-office.gov.uk"))).thenReturn(true);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(200, result.getStatusCode());
        assertEquals("User has an account", result.getBody());
    }

    @Test
    public void shouldReturn404IfUserDoesNotExist() {
        when(USER_SERVICE.userExists(eq("joe.bloggs@digital.cabinet-office.gov.uk"))).thenReturn(false);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(404, result.getStatusCode());
        assertEquals("User not found", result.getBody());
    }

    @Test
    public void shouldReturn400IfRequestIsMissingParameters() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(400, result.getStatusCode());
        assertEquals("Request is missing parameters", result.getBody());
    }

    @Test
    public void shouldReturn400IfRequestIsMissingSessionId() {

    }

    @Test
    public void shouldReturn400IfEmailAddressIsInvalid() {
        when(VALIDATION_SERVICE.validateEmailAddress(eq("joe.bloggs"))).thenReturn(Set.of(EmailValidation.INCORRECT_FORMAT));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(400, result.getStatusCode());
        assertTrue(result.getBody().contains(EmailValidation.INCORRECT_FORMAT.toString()));
    }
}