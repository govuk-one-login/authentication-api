package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.services.UserService;
import uk.gov.di.services.ValidationService;

import java.util.Collections;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.validation.PasswordValidation.NO_NUMBER_INCLUDED;

class SignUpHandlerTest {

    private final Context CONTEXT = mock(Context.class);
    private final UserService USER_SERVICE = mock(UserService.class);
    private final ValidationService VALIDATION_SERVICE = mock(ValidationService.class);
    private SignUpHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new SignUpHandler(USER_SERVICE, VALIDATION_SERVICE);
    }

    @Test
    public void shouldReturn200IfSignUpIsSuccessful() {
        String password = "computer-1";
        when(VALIDATION_SERVICE.validatePassword(eq(password))).thenReturn(Collections.EMPTY_SET);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"password\": \"computer-1\", \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        verify(USER_SERVICE).signUp(eq("joe.bloggs@test.com"), eq(password));

        assertEquals(200, result.getStatusCode());
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(400, result.getStatusCode());
        assertEquals("Request is missing parameters", result.getBody());
    }

    @Test
    public void shouldReturn400IfPasswordFailsValidation() {
        String password = "computer";
        when(VALIDATION_SERVICE.validatePassword(eq(password))).thenReturn(Set.of(NO_NUMBER_INCLUDED));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"password\": \"computer\", \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(400, result.getStatusCode());
        assertTrue(result.getBody().contains(NO_NUMBER_INCLUDED.toString()));
    }
}